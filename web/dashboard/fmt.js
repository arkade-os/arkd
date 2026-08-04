/*
  Formatting and DOM helpers.

  Everything here builds real nodes rather than HTML strings — API values land
  in textContent, so a hostile fail reason or script hex can never become markup.

  Wire-format note: protojson emits int64/uint64 as JSON *strings* and uint32 as
  numbers, so every numeric read goes through num().
*/

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
  while (node.firstChild) node.removeChild(node.firstChild);
  return node;
}

/**
 * Render sats as BTC with the integer part bright and the fraction dim, so the
 * magnitude reads before the precision. `1.85` then a dimmed `418816`.
 */
export function btc(sats, opts = {}) {
  const n = num(sats);
  const neg = n < 0;
  const abs = Math.abs(n);
  const whole = Math.floor(abs / SATS_PER_BTC);
  const frac = String(abs % SATS_PER_BTC).padStart(8, '0');
  const cls = ['amount', opts.large ? 'amount-lg' : null, n === 0 ? 'amount-zero' : null]
    .filter(Boolean).join(' ');
  return el('span', { class: cls, title: `${n.toLocaleString('en-US')} sats` },
    el('span', { class: 'amount-int', text: `${neg ? '-' : ''}${whole}.` }),
    el('span', { class: 'amount-frac', text: frac }),
    opts.unit === false ? null : el('span', { class: 'amount-unit', text: 'BTC' }),
  );
}

/** Same treatment for an already-formatted "0.00000000" string from the admin API. */
export function btcStr(s, opts = {}) {
  const [whole = '0', frac = '00000000'] = String(s ?? '0').split('.');
  const zero = Number(whole) === 0 && Number(frac) === 0;
  const cls = ['amount', opts.large ? 'amount-lg' : null, zero ? 'amount-zero' : null]
    .filter(Boolean).join(' ');
  return el('span', { class: cls },
    el('span', { class: 'amount-int', text: `${whole}.` }),
    el('span', { class: 'amount-frac', text: frac }),
    opts.unit === false ? null : el('span', { class: 'amount-unit', text: 'BTC' }),
  );
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

export function boolBadge(v, yes = 'yes', no = 'no') {
  return v ? badge(yes, 'ok') : badge(no, 'neutral');
}

/** Strip the protobuf enum prefix: CRIME_TYPE_MANUAL_BAN -> manual ban. */
export function enumLabel(v, prefix = '') {
  const s = String(v ?? '');
  if (!s) return '—';
  return s.replace(new RegExp(`^${prefix}`), '').toLowerCase().replace(/_/g, ' ');
}

/** An internal hash link, monospace and middle-truncated. */
export function refLink(href, value, opts = {}) {
  if (!value) return el('span', { class: 'mono', text: '—' });
  return el('a', { href, class: 'mono', title: value },
    opts.full ? value : short(value, opts.head ?? 8, opts.tail ?? 6));
}

/** Date input value (YYYY-MM-DD) to unix seconds. */
export function dateToUnix(value, endOfDay = false) {
  if (!value) return 0;
  const d = new Date(`${value}T${endOfDay ? '23:59:59' : '00:00:00'}`);
  const n = Math.floor(d.getTime() / 1000);
  return Number.isFinite(n) ? n : 0;
}

export function unixToDate(unix) {
  const d = new Date(num(unix) * 1000);
  const p = (x) => String(x).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}
