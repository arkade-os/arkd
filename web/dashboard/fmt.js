/*
  Formatting and DOM helpers.

  Everything here builds real nodes rather than HTML strings — API values land
  in textContent, so a hostile fail reason or script hex can never become markup.

  Wire-format note: protojson emits int64/uint64 as JSON *strings* and uint32 as
  numbers, so every numeric read goes through num().
*/

import { explorerBase, hasIndexer } from './api.js';

const SATS_PER_BTC = 100_000_000;

/** Coerce a protojson scalar to a number. Missing fields default to 0. */
export function num(v) {
  if (v === null || v === undefined || v === '') return 0;
  const n = typeof v === 'number' ? v : Number(v);
  return Number.isFinite(n) ? n : 0;
}

/** Build an element. Children may be nodes or strings (set as text, never HTML). */
export function el(tag, props = {}, ...kids) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') node.className = v;
    else if (k === 'text') node.textContent = String(v);
    else if (k === 'html') throw new Error('el(): raw html is not allowed');
    else if (k.startsWith('on')) node.addEventListener(k.slice(2).toLowerCase(), v);
    else if (k === 'style') for (const [p, pv] of Object.entries(v)) node.style.setProperty(p, pv);
    else if (v === true) node.setAttribute(k, '');
    else node.setAttribute(k, String(v));
  }
  for (const kid of kids.flat()) {
    if (kid === null || kid === undefined || kid === false) continue;
    node.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return node;
}

export function clear(node) {
  node.replaceChildren();
  return node;
}

/** Leading zeros dim, significant digits bright, tail grouped: `0.00 002 324`. */
function amount(neg, whole, frac, opts, title) {
  const digits = `${whole}.${frac.slice(0, 2)} ${frac.slice(2, 5)} ${frac.slice(5)}`;
  const at = digits.search(/[1-9]/);
  return el('span', {
    class: `amount${opts.large ? ' amount-lg' : ''}`,
    title,
  },
    neg ? el('span', { class: 'amount-sig', text: '-' }) : null,
    el('span', { class: 'amount-dim', text: at < 0 ? digits : digits.slice(0, at) }),
    at < 0 ? null : el('span', { class: 'amount-sig', text: digits.slice(at) }),
    opts.unit === false ? null : el('span', { class: 'amount-unit', text: 'BTC' }),
  );
}

/** Sats to BTC. */
export function btc(v, opts = {}) {
  const n = num(v);
  const abs = Math.abs(n);
  return amount(
    n < 0,
    String(Math.floor(abs / SATS_PER_BTC)),
    String(abs % SATS_PER_BTC).padStart(8, '0'),
    opts,
    `${n.toLocaleString('en-US')} sats`,
  );
}

/** Same, for an already-formatted "0.00000000" string from the admin API. */
export function btcStr(s, opts = {}) {
  const [whole = '0', frac = ''] = String(s ?? '0').split('.');
  return amount(whole.startsWith('-'), whole.replace('-', ''), frac.padEnd(8, '0'), opts);
}

export function sats(v) {
  return num(v).toLocaleString('en-US');
}

/** Unix seconds to a local, sortable-looking timestamp. */
export function ts(v) {
  const n = num(v);
  if (!n) return '—';
  const d = new Date(n * 1000);
  const p = (x) => String(x).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

/** Signed, human relative time: "4m ago", "in 2d". */
export function ago(v) {
  const n = num(v);
  if (!n) return '—';
  const delta = Math.round(Date.now() / 1000) - n;
  const past = delta >= 0;
  const s = Math.abs(delta);
  const units = [[86400, 'd'], [3600, 'h'], [60, 'm']];
  for (const [secs, label] of units) {
    if (s >= secs) {
      const q = Math.floor(s / secs);
      return past ? `${q}${label} ago` : `in ${q}${label}`;
    }
  }
  return past ? `${s}s ago` : `in ${s}s`;
}

/** A timestamp cell that leads with relative time and keeps the exact value on hover. */
export function timeCell(v) {
  const n = num(v);
  if (!n) return el('span', { class: 'mono', text: '—' });
  return el('span', { class: 'mono', title: ts(n), text: ago(n) });
}

/** Middle-truncate a hash so both ends stay recognisable. */
export function short(s, head = 8, tail = 6) {
  const v = String(s ?? '');
  if (!v) return '—';
  if (v.length <= head + tail + 1) return v;
  return `${v.slice(0, head)}…${v.slice(-tail)}`;
}

/** Seconds to a compact duration, for settings values like exit delays. */
export function dur(v) {
  const n = num(v);
  if (!n) return '—';
  const d = Math.floor(n / 86400);
  const h = Math.floor((n % 86400) / 3600);
  const m = Math.floor((n % 3600) / 60);
  const s = n % 60;
  return [d && `${d}d`, h && `${h}h`, m && `${m}m`, s && `${s}s`].filter(Boolean).join(' ') || '0s';
}

export function badge(text, tone = 'neutral') {
  return el('span', { class: `badge ${tone}`, text });
}

/** Batch/offchain lifecycle to a badge. Failure always wins the colour. */
export function stageBadge(row) {
  if (row.failed) return badge('failed', 'fail');
  if (row.swept) return badge('swept', 'ok');
  if (row.ended) return badge('ended', 'ok');
  const stage = String(row.stage ?? '').replace(/_STAGE$/, '').replace(/^OFFCHAIN_TX_/, '');
  return badge((stage || 'pending').toLowerCase().replace(/_/g, ' '), 'warn');
}

export function boolBadge(v, yes, no) {
  return v ? badge(yes, 'ok') : badge(no, 'neutral');
}

/** Strip the protobuf enum prefix: CRIME_TYPE_MANUAL_BAN -> manual ban. */
export function enumLabel(v, prefix = '') {
  const s = String(v ?? '');
  if (!s) return '—';
  return s.replace(new RegExp(`^${prefix}`), '').toLowerCase().replace(/_/g, ' ');
}

/** An internal hash link, monospace and middle-truncated. */
export function refLink(href, value, full = false) {
  if (!value) return el('span', { class: 'mono', text: '—' });
  return el('a', { href, class: 'mono', title: value }, full ? value : short(value));
}

/** A txid: the in-console drill-down, then an out-link to the block explorer. */
export function txCell(txid, opts = {}) {
  if (!txid) return el('span', { class: 'mono', text: '—' });

  const label = opts.label ?? (opts.full ? txid : short(txid, opts.head ?? 8, opts.tail ?? 6));
  const inner = opts.href
    ? el('a', { href: opts.href, class: 'mono', title: txid }, label)
    : el('span', { class: 'mono', title: txid, text: label });

  const base = explorerBase();
  if (!base) return inner;

  return el('span', { class: 'tx-cell' }, inner, el('a', {
    class: 'ext',
    href: `${base}/tx/${txid}`,
    target: '_blank',
    rel: 'noopener noreferrer',
    title: 'open in the block explorer',
  }, '↗'));
}

/**
 * A commitment txid. The in-console drill-down is an indexer page, so the link
 * only appears when an indexer is configured — otherwise it would land on
 * "indexer not configured".
 */
export function commitmentCell(txid, opts = {}) {
  return txCell(txid, {
    ...opts,
    href: txid && hasIndexer() ? `#/commitment/${encodeURIComponent(txid)}` : null,
  });
}

/** An outpoint, with the txid carrying the explorer link. */
export function outpointCell(txid, vout, opts = {}) {
  if (!txid) return el('span', { class: 'mono', text: '—' });
  const head = opts.full ? txid : short(txid, opts.head ?? 8, opts.tail ?? 6);
  return txCell(txid, { ...opts, label: `${head}:${vout ?? 0}` });
}

/**
 * Copies `text` to the clipboard. The console never writes to arkd, so commands
 * that would change state are handed over for the operator to run. Falls back to
 * showing the text when the clipboard is unavailable, e.g. served over http.
 */
export function copyButton(text, label) {
  const btn = el('button', { class: 'btn btn-ghost btn-xs', type: 'button', title: text }, label);
  btn.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(text);
      btn.textContent = 'copied';
      setTimeout(() => { btn.textContent = label; }, 1500);
    } catch {
      btn.replaceWith(el('code', { class: 'mono copy-fallback', text }));
    }
  });
  return btn;
}

/** Date input value (YYYY-MM-DD) to unix seconds. */
export function dateToUnix(value, endOfDay = false) {
  if (!value) return 0;
  const d = new Date(`${value}T${endOfDay ? '23:59:59' : '00:00:00'}`);
  const n = Math.floor(d.getTime() / 1000);
  return Number.isFinite(n) ? n : 0;
}

/** The date half of ts(), for a date input's value. */
export function unixToDate(unix) {
  return ts(unix).slice(0, 10);
}
