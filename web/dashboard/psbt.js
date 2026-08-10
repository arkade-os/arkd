/*
  PSBT and raw transaction decoder, in the browser.

  arkd has no decode endpoint and this is a static page, so the bytes are parsed
  here: nothing is signed or sent anywhere, and what is decoded never leaves the
  tab. BIP-174 v0 only; a v2 PSBT is reported rather than half-decoded.
*/

import { el, btc, short, badge } from './fmt.js';
import { card, kv, table, emptyState, blobCell } from './table.js';

const PSBT_MAGIC = [0x70, 0x73, 0x62, 0x74, 0xff];

/* ------------------------------------------------------------------ bytes */

const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

function fromHex(s) {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function fromBase64(s) {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

/** Accept whatever the operator pasted: base64 PSBT, hex PSBT, or hex raw tx. */
function toBytes(text) {
  const s = String(text ?? '').trim().replace(/\s+/g, '');
  if (!s) throw new Error('Nothing to decode.');
  if (/^[0-9a-fA-F]+$/.test(s) && s.length % 2 === 0) return fromHex(s);
  try {
    return fromBase64(s.replace(/-/g, '+').replace(/_/g, '/'));
  } catch {
    throw new Error('That is neither base64 nor hex.');
  }
}

class Reader {
  constructor(b) {
    this.b = b;
    this.i = 0;
    this.view = new DataView(b.buffer, b.byteOffset, b.byteLength);
  }

  need(n) {
    if (this.i + n > this.b.length) throw new Error('Truncated: the data ends in the middle of a field.');
  }

  u8() { this.need(1); return this.b[this.i++]; }
  u16() { this.need(2); const v = this.view.getUint16(this.i, true); this.i += 2; return v; }
  u32() { this.need(4); const v = this.view.getUint32(this.i, true); this.i += 4; return v; }
  i32() { this.need(4); const v = this.view.getInt32(this.i, true); this.i += 4; return v; }
  // Amounts and sequences fit in a double; Bitcoin caps supply well below 2^53.
  u64() { this.need(8); const v = this.view.getBigUint64(this.i, true); this.i += 8; return Number(v); }

  varint() {
    const tag = this.u8();
    if (tag < 0xfd) return tag;
    if (tag === 0xfd) return this.u16();
    if (tag === 0xfe) return this.u32();
    return this.u64();
  }

  take(n) { this.need(n); const out = this.b.subarray(this.i, this.i + n); this.i += n; return out; }
  varbytes() { return this.take(this.varint()); }
  get done() { return this.i >= this.b.length; }
}

/** Double SHA-256, big-endian reversed: a txid. Needs a secure context. */
async function txidOf(raw) {
  if (!globalThis.crypto?.subtle) return '';
  const once = await crypto.subtle.digest('SHA-256', raw);
  const twice = await crypto.subtle.digest('SHA-256', once);
  return hex(new Uint8Array(twice).reverse());
}

/* ------------------------------------------------------------- structures */

function readWitness(r) {
  const items = [];
  const count = r.varint();
  for (let i = 0; i < count; i += 1) items.push(r.varbytes());
  return items;
}

function readTx(r) {
  const start = r.i;
  const version = r.i32();
  const afterVersion = r.i;

  const segwit = r.b[r.i] === 0x00 && r.b[r.i + 1] === 0x01;
  if (segwit) r.i += 2;

  const bodyStart = r.i;
  const inputs = [];
  const inCount = r.varint();
  for (let i = 0; i < inCount; i += 1) {
    const hash = r.take(32).slice().reverse();
    inputs.push({
      txid: hex(hash),
      vout: r.u32(),
      scriptSig: r.varbytes(),
      sequence: r.u32(),
    });
  }

  const outputs = [];
  const outCount = r.varint();
  for (let i = 0; i < outCount; i += 1) outputs.push({ amount: r.u64(), script: r.varbytes() });
  const bodyEnd = r.i;

  if (segwit) for (const input of inputs) input.witness = readWitness(r);
  const locktimeAt = r.i;
  const locktime = r.u32();

  // The txid commits to the non-witness serialization, so stitch it back
  // together from the spans we just walked instead of re-encoding by hand.
  const preimage = new Uint8Array([
    ...r.b.subarray(start, afterVersion),
    ...r.b.subarray(bodyStart, bodyEnd),
    ...r.b.subarray(locktimeAt, locktimeAt + 4),
  ]);

  return { version, locktime, inputs, outputs, segwit, preimage };
}

/** One BIP-174 key-value map, up to its 0x00 separator. */
function readMap(r) {
  const fields = [];
  for (;;) {
    if (r.done) throw new Error('Truncated: a key-value map has no separator.');
    const keyLen = r.varint();
    if (keyLen === 0) return fields;
    const key = r.take(keyLen);
    fields.push({ type: key[0], key, keyData: key.subarray(1), value: r.varbytes() });
  }
}

async function decode(text) {
  const bytes = toBytes(text);
  const isPsbt = PSBT_MAGIC.every((b, i) => bytes[i] === b);

  if (!isPsbt) {
    const tx = readTx(new Reader(bytes));
    return {
      format: 'Raw transaction',
      txid: await txidOf(tx.preimage),
      tx,
      globals: [],
      inputFields: tx.inputs.map(() => []),
      outputFields: tx.outputs.map(() => []),
      size: bytes.length,
    };
  }

  const r = new Reader(bytes);
  r.i = PSBT_MAGIC.length;

  const globals = readMap(r);
  const unsigned = globals.find((f) => f.type === 0x00);
  if (!unsigned) {
    throw new Error('This looks like a PSBT v2. Only v0 (with an unsigned tx) is decoded here.');
  }

  const tx = readTx(new Reader(unsigned.value));
  const inputFields = tx.inputs.map(() => readMap(r));
  const outputFields = tx.outputs.map(() => readMap(r));

  return {
    format: 'PSBT v0',
    txid: await txidOf(tx.preimage),
    tx,
    globals: globals.filter((f) => f.type !== 0x00),
    inputFields,
    outputFields,
    size: bytes.length,
  };
}

/* ---------------------------------------------------------------- scripts */

// Named where it helps; anything else prints as OP_<n>.
const OPCODES = {
  0x00: 'OP_0', 0x4c: 'OP_PUSHDATA1', 0x4d: 'OP_PUSHDATA2', 0x4e: 'OP_PUSHDATA4',
  0x4f: 'OP_1NEGATE', 0x61: 'OP_NOP', 0x63: 'OP_IF', 0x64: 'OP_NOTIF', 0x67: 'OP_ELSE',
  0x68: 'OP_ENDIF', 0x69: 'OP_VERIFY', 0x6a: 'OP_RETURN', 0x6b: 'OP_TOALTSTACK',
  0x6c: 'OP_FROMALTSTACK', 0x6d: 'OP_2DROP', 0x6e: 'OP_2DUP', 0x6f: 'OP_3DUP',
  0x73: 'OP_IFDUP', 0x74: 'OP_DEPTH', 0x75: 'OP_DROP', 0x76: 'OP_DUP', 0x77: 'OP_NIP',
  0x78: 'OP_OVER', 0x79: 'OP_PICK', 0x7a: 'OP_ROLL', 0x7b: 'OP_ROT', 0x7c: 'OP_SWAP',
  0x7d: 'OP_TUCK', 0x82: 'OP_SIZE', 0x87: 'OP_EQUAL', 0x88: 'OP_EQUALVERIFY',
  0x8b: 'OP_1ADD', 0x8c: 'OP_1SUB', 0x91: 'OP_NOT', 0x92: 'OP_0NOTEQUAL', 0x93: 'OP_ADD',
  0x94: 'OP_SUB', 0x9a: 'OP_BOOLAND', 0x9b: 'OP_BOOLOR', 0x9c: 'OP_NUMEQUAL',
  0x9d: 'OP_NUMEQUALVERIFY', 0x9e: 'OP_NUMNOTEQUAL', 0x9f: 'OP_LESSTHAN',
  0xa0: 'OP_GREATERTHAN', 0xa1: 'OP_LESSTHANOREQUAL', 0xa2: 'OP_GREATERTHANOREQUAL',
  0xa3: 'OP_MIN', 0xa4: 'OP_MAX', 0xa5: 'OP_WITHIN', 0xa6: 'OP_RIPEMD160',
  0xa7: 'OP_SHA1', 0xa8: 'OP_SHA256', 0xa9: 'OP_HASH160', 0xaa: 'OP_HASH256',
  0xab: 'OP_CODESEPARATOR', 0xac: 'OP_CHECKSIG', 0xad: 'OP_CHECKSIGVERIFY',
  0xae: 'OP_CHECKMULTISIG', 0xaf: 'OP_CHECKMULTISIGVERIFY',
  0xb1: 'OP_CHECKLOCKTIMEVERIFY', 0xb2: 'OP_CHECKSEQUENCEVERIFY', 0xba: 'OP_CHECKSIGADD',
};

/** Disassemble a script. Malformed tails are reported, not thrown on. */
function asm(script) {
  const out = [];
  let i = 0;
  while (i < script.length) {
    const op = script[i];
    i += 1;
    if (op > 0x00 && op < 0x4c) {
      out.push(hex(script.subarray(i, i + op)));
      i += op;
    } else if (op >= 0x4c && op <= 0x4e) {
      const width = op === 0x4c ? 1 : op === 0x4d ? 2 : 4;
      let n = 0;
      for (let k = 0; k < width; k += 1) n += script[i + k] << (8 * k);
      i += width;
      out.push(`${OPCODES[op]} ${hex(script.subarray(i, i + n))}`);
      i += n;
    } else if (op >= 0x51 && op <= 0x60) {
      out.push(`OP_${op - 0x50}`);
    } else {
      out.push(OPCODES[op] ?? `OP_${op}`);
    }
    if (i > script.length) return `${out.join(' ')} [truncated push]`;
  }
  return out.join(' ');
}

/** Best-effort output type, from the standard script templates. */
function scriptType(s) {
  if (!s?.length) return 'empty';
  if (s[0] === 0x6a) return 'OP_RETURN';
  if (s.length === 34 && s[0] === 0x51 && s[1] === 0x20) return 'P2TR';
  if (s.length === 22 && s[0] === 0x00 && s[1] === 0x14) return 'P2WPKH';
  if (s.length === 34 && s[0] === 0x00 && s[1] === 0x20) return 'P2WSH';
  if (s.length === 25 && s[0] === 0x76 && s[1] === 0xa9) return 'P2PKH';
  if (s.length === 23 && s[0] === 0xa9 && s[s.length - 1] === 0x87) return 'P2SH';
  if (s[0] >= 0x50 && s[0] <= 0x60) return `witness v${s[0] === 0x00 ? 0 : s[0] - 0x50}`;
  return 'non-standard';
}

/* ----------------------------------------------------------- field naming */

const GLOBAL_TYPES = {
  0x01: 'XPub', 0x02: 'Tx version', 0x03: 'Fallback locktime', 0x04: 'Input count',
  0x05: 'Output count', 0x06: 'Tx modifiable', 0xfb: 'PSBT version', 0xfc: 'Proprietary',
};

const INPUT_TYPES = {
  0x00: 'Non-witness UTXO', 0x01: 'Witness UTXO', 0x02: 'Partial signature',
  0x03: 'Sighash type', 0x04: 'Redeem script', 0x05: 'Witness script',
  0x06: 'BIP32 derivation', 0x07: 'Final scriptSig', 0x08: 'Final scriptWitness',
  0x09: 'PoR commitment', 0x0a: 'RIPEMD160 preimage', 0x0b: 'SHA256 preimage',
  0x0c: 'HASH160 preimage', 0x0d: 'HASH256 preimage', 0x0e: 'Previous txid',
  0x0f: 'Output index', 0x10: 'Sequence', 0x11: 'Required time locktime',
  0x12: 'Required height locktime', 0x13: 'Taproot key signature',
  0x14: 'Taproot script signature', 0x15: 'Taproot leaf script',
  0x16: 'Taproot BIP32 derivation', 0x17: 'Taproot internal key',
  0x18: 'Taproot merkle root', 0xfc: 'Proprietary',
};

const OUTPUT_TYPES = {
  0x00: 'Redeem script', 0x01: 'Witness script', 0x02: 'BIP32 derivation',
  0x03: 'Amount', 0x04: 'Script', 0x05: 'Taproot internal key', 0x06: 'Taproot tree',
  0x07: 'Taproot BIP32 derivation', 0xfc: 'Proprietary',
};

// Ark keeps its own fields in the PSBT unknowns under key type 222, with the
// field name as key data (see pkg/ark-lib/txutils/psbt_fields.go).
const ARK_KEY_TYPE = 222;
const ARK_FIELDS = ['taptree', 'expiry', 'cosigner', 'condition'];

/** The key type byte is optional: the oldest fields were written as a bare name. */
function arkFieldName(key) {
  const bytes = key[0] === ARK_KEY_TYPE ? key.subarray(1) : key;
  const name = new TextDecoder().decode(bytes);
  for (const field of ARK_FIELDS) {
    if (!name.startsWith(field)) continue;
    // Only the cosigner field carries data after its name: a 4-byte index.
    if (field === 'cosigner' && bytes.length === field.length + 4) {
      const view = new DataView(bytes.buffer, bytes.byteOffset + field.length, 4);
      return `ark: cosigner ${view.getUint32(0)}`;
    }
    if (name === field) return `ark: ${field}`;
  }
  return null;
}

const SIGHASH_NAMES = {
  0x00: 'DEFAULT', 0x01: 'ALL', 0x02: 'NONE', 0x03: 'SINGLE',
  0x81: 'ALL|ANYONECANPAY', 0x82: 'NONE|ANYONECANPAY', 0x83: 'SINGLE|ANYONECANPAY',
};

function scriptNode(script) {
  return el('div', {},
    el('div', { class: 'mono asm', text: asm(script) }),
    el('div', { class: 'subline mono', text: `${script.length} bytes · ${hex(script)}` }),
  );
}

function witnessNode(items) {
  if (!items.length) return el('span', { class: 'mono dim', text: 'empty' });
  return el('ol', { class: 'json-list' }, items.map((item) => el('li', {},
    el('span', { class: 'mono', text: item.length ? hex(item) : '<empty>' }),
  )));
}

/** Render one key-value field as a [label, node] pair for kv(). */
function fieldPair(field, names) {
  const standard = names[field.type];
  // A standard key type wins, except under 222 where ark writes its own fields.
  // Legacy ark keys carry no type byte at all, so they surface as unknowns.
  const ark = field.type === ARK_KEY_TYPE || !standard ? arkFieldName(field.key) : null;
  const label = ark ?? standard ?? `Unknown (key type ${field.type})`;
  const v = field.value;

  try {
    if (ark === 'ark: condition') return [label, witnessNode(readWitness(new Reader(v)))];
    if (ark === 'ark: taptree') return [label, tapTreeNode(v)];
    if (ark?.startsWith('ark: cosigner')) return [label, el('span', { class: 'mono', text: hex(v) })];

    if (names === INPUT_TYPES) {
      if (field.type === 0x01) { // witness utxo: amount then script
        const r = new Reader(v);
        const amount = r.u64();
        return [label, el('div', {}, btc(amount), scriptNode(r.varbytes()))];
      }
      if (field.type === 0x03) {
        const code = new Reader(v).u32();
        return [label, el('span', { class: 'mono', text: `${SIGHASH_NAMES[code] ?? 'custom'} (0x${code.toString(16)})` })];
      }
      if (field.type === 0x08) return [label, witnessNode(readWitness(new Reader(v)))];
      if (field.type === 0x15) { // tap leaf: script || leaf version, control block in the key
        const script = v.subarray(0, v.length - 1);
        const control = field.keyData;
        return [label, el('div', {},
          scriptNode(script),
          el('div', { class: 'subline mono', text: `leaf version 0x${v[v.length - 1].toString(16)} · control block ${short(hex(control), 16, 8)} · ${Math.max(0, (control.length - 33) / 32)} merkle steps` }),
        )];
      }
      if (field.type === 0x04 || field.type === 0x05) return [label, scriptNode(v)];
    }

    if (names === OUTPUT_TYPES) {
      if (field.type === 0x00 || field.type === 0x01 || field.type === 0x04) return [label, scriptNode(v)];
      if (field.type === 0x03) return [label, btc(new Reader(v).u64())];
      if (field.type === 0x06) return [label, tapTreeNode(v)];
    }
  } catch {
    // A field that does not parse is still worth showing raw.
  }

  const raw = hex(v);
  return [label, raw.length > 80
    ? blobCell(raw, `${v.length} bytes`)
    : el('span', { class: 'mono', text: raw || '<empty>' })];
}

/** BIP-371 layout, which ark reuses: depth / leaf version / script, no count. */
function tapTreeNode(value) {
  const r = new Reader(value);
  const leaves = [];
  while (!r.done) leaves.push({ depth: r.u8(), version: r.u8(), script: r.varbytes() });
  if (!leaves.length) return el('span', { class: 'mono dim', text: 'empty' });
  return el('div', {}, leaves.map((leaf) => el('div', { class: 'leaf' },
    el('div', { class: 'subline mono', text: `depth ${leaf.depth} · version 0x${leaf.version.toString(16)}` }),
    scriptNode(leaf.script),
  )));
}

/* ------------------------------------------------------------------ modal */

/** A magnifier next to a PSBT that opens its decoded fields in a modal. */
export function decodeIcon(value, title = 'PSBT') {
  if (!value) return el('span', { class: 'mono', text: '—' });
  return el('button', {
    class: 'icon-btn',
    type: 'button',
    title: `decode ${title}`,
    'aria-label': `decode ${title}`,
    onclick: () => void openDecoded(value, title),
  }, '⌕');
}

async function openDecoded(value, title) {
  const body = el('div', { class: 'decode-body' });
  const dialog = el('dialog', { class: 'decode-modal' },
    el('div', { class: 'decode-head' },
      el('h2', { text: title }),
      el('button', { class: 'btn btn-ghost btn-xs', type: 'button', onclick: () => dialog.close() }, 'Close'),
    ),
    body,
  );
  // <dialog> keeps Esc and the backdrop for free; removing it on close keeps
  // the DOM from collecting one modal per click.
  dialog.addEventListener('close', () => dialog.remove());
  document.body.append(dialog);
  dialog.showModal();

  try {
    body.append(...render(await decode(value)));
  } catch (err) {
    body.append(card(null, emptyState('Could not decode', err?.message ?? String(err))));
  }
}

function render(d) {
  const { tx } = d;
  const totalOut = tx.outputs.reduce((sum, o) => sum + o.amount, 0);
  // Input amounts only exist when every input carries a witness utxo.
  const amounts = d.inputFields.map((fields) => {
    const utxo = fields.find((f) => f.type === 0x01);
    return utxo ? new Reader(utxo.value).u64() : null;
  });
  const known = amounts.every((a) => a !== null);
  const totalIn = known ? amounts.reduce((sum, a) => sum + a, 0) : null;

  const out = [card('Transaction', kv([
    ['Format', badge(d.format, 'neutral')],
    ['Txid', el('span', { class: 'mono', text: d.txid || 'needs https or localhost' })],
    ['Version', el('span', { class: 'mono', text: String(tx.version) })],
    ['Locktime', el('span', { class: 'mono', text: String(tx.locktime) })],
    ['Size', el('span', { class: 'mono', text: `${d.size} bytes` })],
    ['Inputs', el('span', { class: 'mono', text: String(tx.inputs.length) })],
    ['Outputs', el('span', { class: 'mono', text: String(tx.outputs.length) })],
    ['Total in', known ? btc(totalIn) : el('span', { class: 'mono dim', text: 'no witness utxo' })],
    ['Total out', btc(totalOut)],
    ['Fee', known ? btc(totalIn - totalOut) : el('span', { class: 'mono dim', text: '—' })],
  ]))];

  if (d.globals.length) {
    out.push(card('Global fields', kv(d.globals.map((f) => fieldPair(f, GLOBAL_TYPES)))));
  }

  tx.inputs.forEach((input, i) => {
    const pairs = [
      ['Outpoint', el('span', { class: 'mono', text: `${input.txid}:${input.vout}` })],
      ['Sequence', el('span', { class: 'mono', text: `0x${input.sequence.toString(16).padStart(8, '0')}` })],
      amounts[i] === null ? null : ['Amount', btc(amounts[i])],
      input.scriptSig.length ? ['scriptSig', scriptNode(input.scriptSig)] : null,
      input.witness?.length ? ['Witness', witnessNode(input.witness)] : null,
      ...d.inputFields[i].map((f) => fieldPair(f, INPUT_TYPES)),
    ].filter(Boolean);
    out.push(card(`Input ${i}`, kv(pairs), `${d.inputFields[i].length} psbt fields`));
  });

  out.push(card('Outputs', table([
    { label: '#', cls: 'num', cell: (o, i) => String(i) },
    { label: 'Amount', cls: 'num', cell: (o) => btc(o.amount) },
    { label: 'Type', cell: (o) => badge(scriptType(o.script), 'neutral') },
    { label: 'Script', cls: 'wrap', cell: (o) => scriptNode(o.script) },
  ], tx.outputs)));

  d.outputFields.forEach((fields, i) => {
    if (!fields.length) return;
    out.push(card(`Output ${i} fields`, kv(fields.map((f) => fieldPair(f, OUTPUT_TYPES)))));
  });

  return out;
}
