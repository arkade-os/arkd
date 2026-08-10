/*
  The generic renderer.

  Most panels in this console are "GET a URL, show a table". Those are declared
  as descriptors in panels.js and driven from here, so adding an endpoint later
  costs a few lines instead of a new file. The three panels that carry real
  logic (solvency, batch, offchain tx) are written by hand instead.
*/

import { el, clear, num, short } from './fmt.js';
import { adminGet, indexerGet, ApiError } from './api.js';

/* ------------------------------------------------------------------ states */

export function skeleton() {
  return el('div', { class: 'skeleton' },
    el('div', { class: 'skeleton-row' }),
    el('div', { class: 'skeleton-row' }),
    el('div', { class: 'skeleton-row' }),
  );
}

export function emptyState(title, hint) {
  return el('div', { class: 'state' },
    el('p', { class: 'state-title', text: title }),
    hint ? el('p', { text: hint }) : null,
  );
}

export function errorState(err) {
  const message = err?.message ?? String(err);
  // grpc-gateway often surfaces the same string as both, so only show the
  // detail when it actually adds something.
  const detail = err instanceof ApiError && err.detail !== message ? err.detail : '';
  return el('div', { class: 'state error' },
    el('p', { class: 'state-title', text: 'Could not load this' }),
    el('p', { text: message }),
    detail ? el('p', {}, el('code', { text: detail })) : null,
  );
}

/* ------------------------------------------------------------------ tables */

// Rows rendered before the table truncates itself. A batch can hold tens of
// thousands of leaf VTXOs; building that many rows blocks the main thread long
// enough that the panel looks hung, so we cap and offer an explicit override.
const ROW_CAP = 500;

/**
 * cols: [{ label, cell(row, i) -> Node|string, cls?: 'num'|'mono'|'wrap', width?,
 *          sortValue?: (row) => number|string }]
 *
 * A column with sortValue gets a clickable header; the first click sorts it
 * descending. Sorting is client-side over every row, not just the rendered cap.
 */
export function table(cols, rows) {
  const wrap = el('div', {});
  let limit = ROW_CAP;
  let sortCol = null;
  let descending = true;

  const ordered = () => {
    if (sortCol === null) return rows;
    const key = cols[sortCol].sortValue;
    const dir = descending ? -1 : 1;
    // Slice: the caller's array order is the panel's default, restored by a
    // third click on the header.
    return rows.slice().sort((a, b) => {
      const x = key(a);
      const y = key(b);
      return (x < y ? -1 : x > y ? 1 : 0) * dir;
    });
  };

  const header = (c, i) => {
    if (!c.sortValue) return c.label;
    const on = sortCol === i;
    return el('button', {
      class: `th-sort${on ? ' on' : ''}`,
      type: 'button',
      // Descending first, then ascending, then back to the panel's own order.
      onclick: () => {
        if (!on) { sortCol = i; descending = true; } else if (descending) { descending = false; } else { sortCol = null; }
        draw();
      },
    }, c.label, el('span', { class: 'caret', text: on ? (descending ? '▾' : '▴') : '⇅' }));
  };

  const draw = () => {
    const all = ordered();
    const shown = limit === null ? all : all.slice(0, limit);

    const thead = el('thead', {}, el('tr', {}, cols.map((c, i) => el('th', {
      scope: 'col',
      style: c.width ? { width: c.width } : undefined,
      'aria-sort': sortCol === i ? (descending ? 'descending' : 'ascending') : undefined,
    }, header(c, i)))));

    // One fragment, one insertion: appending rows individually forces the
    // browser to re-evaluate layout far more than it needs to.
    const frag = document.createDocumentFragment();
    for (let i = 0; i < shown.length; i += 1) {
      const tr = el('tr', {});
      for (const c of cols) {
        tr.append(el('td', { class: c.cls || undefined }, c.cell(shown[i], i) ?? '—'));
      }
      frag.append(tr);
    }
    const tbody = el('tbody', {});
    tbody.append(frag);

    clear(wrap).append(
      el('div', { class: 'table-wrap' }, el('table', { class: 'grid' }, thead, tbody)),
    );

    if (limit !== null && all.length > limit) {
      wrap.append(el('div', { class: 'table-more' },
        el('span', {
          text: `Showing the first ${limit.toLocaleString('en-US')} of ${all.length.toLocaleString('en-US')} rows.`,
        }),
        el('button', {
          class: 'btn btn-ghost',
          type: 'button',
          onclick: () => { limit = null; draw(); },
        }, 'Render all'),
      ));
    }
  };

  draw();
  return wrap;
}

/** pairs: [[label, Node|string], ...]. Entries with a null value are dropped. */
export function kv(pairs) {
  const kept = pairs.filter(([, v]) => v !== null && v !== undefined);
  return el('dl', { class: 'kv' }, kept.flatMap(([k, v]) => [
    el('dt', { text: k }),
    el('dd', {}, v),
  ]));
}

/* ------------------------------------------------------------------- blobs */

/** A long opaque value (a proof, a script) collapsed behind a disclosure. */
export function blobCell(value, summary) {
  const raw = String(value ?? '');
  if (!raw) return el('span', { class: 'mono', text: '—' });
  return el('details', { class: 'blob' },
    el('summary', { class: 'mono', text: summary ?? short(raw, 28, 0) }),
    el('pre', { text: raw }),
  );
}

/** Pretty-printed JSON in full, for detail pages with room to show it. */
export function jsonBlock(value) {
  const raw = String(value ?? '');
  if (!raw) return el('span', { class: 'mono', text: '—' });
  let body = raw;
  try { body = JSON.stringify(JSON.parse(raw), null, 2); } catch { /* not json, show raw */ }
  return el('pre', { class: 'json-block', text: body });
}

/** The same, collapsed to one line. Intent messages are named by their type. */
export function jsonCell(value) {
  const raw = String(value ?? '');
  if (!raw) return el('span', { class: 'mono', text: '—' });

  let type;
  try { type = JSON.parse(raw)?.type; } catch { return blobCell(raw); }

  return el('details', { class: 'blob' },
    el('summary', { class: 'mono', text: type ?? short(raw, 28, 0) }),
    jsonBlock(raw),
  );
}

export function card(title, body, note) {
  return el('section', { class: 'card' },
    title ? el('header', { class: 'card-head' },
      el('h2', { class: 'card-title', text: title }),
      note ? el('span', { class: 'card-note' }, note) : null,
    ) : null,
    body,
  );
}

/** Stack several bare panels under one heading and reload them together. */
export function combine(title, sub, parts) {
  return {
    node: el('div', {}, panelHead(title, sub), parts.map((p) => p.node)),
    reload: () => Promise.all(parts.map((p) => p.reload())),
  };
}

export function panelHead(title, sub) {
  return el('header', { class: 'panel-head' },
    el('p', { class: 'eyebrow', text: 'arkd' }),
    el('h1', { class: 'panel-title', text: title }),
    sub ? el('p', { class: 'panel-sub', text: sub }) : null,
  );
}

/* ----------------------------------------------------------------- filters */

/**
 * spec: [{ name, label, type: 'date'|'text'|'number'|'check'|'select', value, options, grow, placeholder }]
 * Returns { node, values() } — values() reads the live control state.
 */
function filterBar(spec, onApply) {
  const inputs = new Map();

  const controls = spec.map((f) => {
    if (f.type === 'check') {
      const input = el('input', { type: 'checkbox', id: `f-${f.name}` });
      input.checked = Boolean(f.value);
      input.addEventListener('change', onApply);
      inputs.set(f.name, () => input.checked);
      return el('label', { class: 'filter-check', for: `f-${f.name}` }, input, f.label);
    }

    if (f.type === 'select') {
      const select = el('select', { id: `f-${f.name}` },
        f.options.map((o) => el('option', { value: o.value, selected: o.value === f.value }, o.label)));
      select.value = f.value;
      select.addEventListener('change', onApply);
      inputs.set(f.name, () => select.value);
      return el('label', { class: 'filter' }, el('span', { text: f.label }), select);
    }

    const input = el('input', {
      type: f.type === 'number' ? 'number' : f.type === 'date' ? 'date' : 'text',
      id: `f-${f.name}`,
      value: f.value ?? '',
      placeholder: f.placeholder,
      min: f.type === 'number' ? '0' : undefined,
    });
    input.addEventListener('change', onApply);
    input.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); onApply(); } });
    inputs.set(f.name, () => input.value);
    return el('label', { class: `filter${f.grow ? ' grow' : ''}` }, el('span', { text: f.label }), input);
  });

  return {
    node: el('div', { class: 'filters' }, controls),
    values() {
      const out = {};
      for (const [name, read] of inputs) out[name] = read();
      return out;
    },
  };
}

/* ------------------------------------------------------------- list driver */

/**
 * Drives a descriptor into a live panel. Returns { node, reload }.
 *
 * desc: {
 *   title, sub, source: 'admin'|'indexer',
 *   path: string | (values) => string,
 *   params?: (values) => object,
 *   key: string,                       // response field holding the array
 *   cols, filters?, empty?, emptyHint?,
 *   requires?: (values) => string|null, // block the request until an input is given
 *   sort?: (a, b) => number,           // row comparator; defaults to recent first
 *   note?: (rows, body) => string,
 *   enrich?: async (rows) => void,     // second read, joined onto the rows in place
 * }
 */
// Every list here is a log of things that happened, so the newest row is the one
// worth seeing first. Rows without any of these fields keep the server's order
// (Array.sort is stable), and a panel with a different natural order sets desc.sort.
const TIME_FIELDS = ['createdAt', 'startedAt', 'expiredAt', 'timestamp'];

function recentFirst(a, b) {
  const f = TIME_FIELDS.find((k) => a?.[k] != null || b?.[k] != null);
  return f ? num(b[f]) - num(a[f]) : 0;
}

export function listPanel(desc) {
  const body = el('div', {});
  const node = el('div', {}, desc.bare ? null : panelHead(desc.title, desc.sub));

  let bar = null;
  if (desc.filters?.length) {
    bar = filterBar(desc.filters, () => void reload());
    node.append(bar.node);
  }
  node.append(body);

  // Changing a filter twice in a row leaves two requests in flight. Without this
  // the slower one can land last and paint results for a filter nobody selected.
  let gen = 0;

  async function reload() {
    const mine = ++gen;
    const values = bar ? bar.values() : {};

    const missing = desc.requires?.(values);
    if (missing) {
      clear(body).append(card(null, emptyState(missing)));
      return;
    }

    clear(body).append(card(null, skeleton()));

    try {
      const get = desc.source === 'indexer' ? indexerGet : adminGet;
      const path = typeof desc.path === 'function' ? desc.path(values) : desc.path;
      const res = await get(path, desc.params?.(values));
      if (mine !== gen) return;
      const rows = (res?.[desc.key] ?? []).slice();

      // Allowed to fail: the rows still render, just without the joined field.
      if (desc.enrich) await desc.enrich(rows);
      if (mine !== gen) return;

      rows.sort(desc.sort ?? recentFirst);

      clear(body);
      if (!rows.length) {
        body.append(card(null, emptyState(desc.empty ?? 'Nothing here', desc.emptyHint)));
        return;
      }
      const note = desc.note?.(rows, res) ?? `${rows.length} ${rows.length === 1 ? 'row' : 'rows'}`;
      body.append(card(desc.cardTitle ?? desc.title, table(desc.cols, rows), note));
    } catch (err) {
      if (mine !== gen) return;
      clear(body).append(card(null, errorState(err)));
    }
  }

  return { node, reload };
}

/**
 * Same idea for endpoints that return one object rather than a list.
 * desc: { title, sub, source, path, params?, filters?, pick?: (res) => object,
 *         render: (data, values) => Node }
 */
export function objectPanel(desc) {
  const body = el('div', {});
  const node = el('div', {}, desc.bare ? null : panelHead(desc.title, desc.sub));

  let bar = null;
  if (desc.filters?.length) {
    bar = filterBar(desc.filters, () => void reload());
    node.append(bar.node);
  }
  node.append(body);

  // Same stale-response guard as listPanel: the last request to be issued is the
  // only one allowed to paint.
  let gen = 0;

  async function reload() {
    const mine = ++gen;
    const values = bar ? bar.values() : {};
    clear(body).append(card(null, skeleton()));
    try {
      const get = desc.source === 'indexer' ? indexerGet : adminGet;
      const path = typeof desc.path === 'function' ? desc.path(values) : desc.path;
      const res = await get(path, desc.params?.(values));
      if (mine !== gen) return;
      const data = desc.pick ? desc.pick(res) : res;
      clear(body).append(desc.render(data ?? {}, values));
    } catch (err) {
      if (mine !== gen) return;
      clear(body).append(card(null, errorState(err)));
    }
  }

  return { node, reload };
}
