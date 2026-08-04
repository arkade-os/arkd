/*
  Indexer drill-downs.

  These hang off the admin views: a batch row gives you a commitment txid, and
  from there the tree, the forfeits, the connectors, and whatever swept it. The
  indexer is unauthenticated and lives on the public port, so none of this sends
  the macaroon.
*/

import { el, clear, btc, num, sats, short, ts, timeCell, badge, boolBadge, refLink, enumLabel } from './fmt.js';
import { indexerGet } from './api.js';
import { card, kv, table, panelHead, skeleton, errorState, emptyState } from './table.js';

/* ------------------------------------------------------------- commitment */

export function commitmentPanel(txid) {
  const body = el('div', {});
  const node = el('div', {}, panelHead('Commitment transaction', txid), body);

  async function reload() {
    clear(body).append(card(null, skeleton()));
    try {
      const enc = encodeURIComponent(txid);
      // Forfeits and connectors are optional: a batch with only boarding inputs
      // has neither, and the indexer 404s rather than returning an empty list.
      const [tx, forfeits, connectors] = await Promise.all([
        indexerGet(`/v1/indexer/commitmentTx/${enc}`),
        indexerGet(`/v1/indexer/commitmentTx/${enc}/forfeitTxs`).then((r) => r.txids ?? []).catch(() => []),
        indexerGet(`/v1/indexer/commitmentTx/${enc}/connectors`).then((r) => r.connectors ?? []).catch(() => []),
      ]);

      const batches = Object.entries(tx.batches ?? {});
      const trees = await Promise.all(batches.map(([vout]) => loadBatchOutput(txid, vout)));

      clear(body).append(...render(txid, tx, forfeits, connectors, batches, trees));
    } catch (err) {
      clear(body).append(card(null, errorState(err)));
    }
  }

  return { node, reload };
}

async function loadBatchOutput(txid, vout) {
  const base = `/v1/indexer/batch/${encodeURIComponent(txid)}/${encodeURIComponent(vout)}`;
  const [tree, leaves, sweeps] = await Promise.all([
    indexerGet(`${base}/tree`).then((r) => r.vtxoTree ?? []).catch(() => []),
    indexerGet(`${base}/tree/leaves`).then((r) => r.leaves ?? []).catch(() => []),
    indexerGet(`${base}/sweepTxs`).then((r) => r.sweptBy ?? []).catch(() => []),
  ]);
  return { tree, leaves, sweeps };
}

function render(txid, tx, forfeits, connectors, batches, trees) {
  const out = [];

  out.push(el('div', { class: 'cols-2' },
    card('Transaction', kv([
      ['Txid', el('span', { class: 'mono', text: txid })],
      ['Started', el('span', { class: 'mono', text: ts(tx.startedAt) })],
      ['Ended', el('span', { class: 'mono', text: num(tx.endedAt) ? ts(tx.endedAt) : '—' })],
      ['Batch outputs', el('span', { class: 'mono', text: String(batches.length) })],
      ['Admin view', refLink(`#/batch/${encodeURIComponent(txid)}`, 'open batch detail', { full: true })],
    ])),
    card('Totals', kv([
      ['Input amount', btc(tx.totalInputAmount)],
      ['Input VTXOs', el('span', { class: 'mono', text: sats(tx.totalInputVtxos) })],
      ['Output amount', btc(tx.totalOutputAmount)],
      ['Output VTXOs', el('span', { class: 'mono', text: sats(tx.totalOutputVtxos) })],
    ])),
  ));

  batches.forEach(([vout, batch], i) => {
    const { tree, leaves, sweeps } = trees[i];
    out.push(card(`Batch output ${txid.slice(0, 8)}…:${vout}`, el('div', {},
      kv([
        ['Amount', btc(batch.totalOutputAmount)],
        ['VTXOs', el('span', { class: 'mono', text: sats(batch.totalOutputVtxos) })],
        ['Expires', el('span', { class: 'mono', title: ts(batch.expiresAt), text: `${ts(batch.expiresAt)}` })],
        ['Swept', boolBadge(batch.swept, 'swept', 'not swept')],
        ['Tree nodes', el('span', { class: 'mono', text: String(tree.length) })],
        ['Leaves', el('span', { class: 'mono', text: String(leaves.length) })],
        ['Swept by', sweeps.length
          ? el('span', { class: 'mono' }, sweeps.map((s, j) => el('span', {}, j ? ', ' : '', short(s))))
          : null],
      ]),
      tree.length ? treeTable(tree) : emptyState('No tree', 'This batch output has no VTXO tree.'),
    )));
  });

  out.push(el('div', { class: 'cols-2' },
    forfeits.length
      ? card('Forfeit transactions', table(
        [{ label: 'Txid', cls: 'mono', cell: (t) => t }],
        forfeits,
      ), `${forfeits.length} forfeits`)
      : card('Forfeit transactions', emptyState('None', 'No VTXO inputs required a forfeit.')),
    connectors.length
      ? card('Connectors', table(
        [
          { label: 'Txid', cls: 'mono', cell: (n) => short(n.txid, 12, 8) },
          { label: 'Children', cls: 'num', cell: (n) => String(Object.keys(n.children ?? {}).length) },
        ],
        connectors,
      ), `${connectors.length} nodes`)
      : card('Connectors', emptyState('None', 'This batch has no connector tree.')),
  ));

  return out;
}

function treeTable(tree) {
  return table([
    { label: 'Node txid', cls: 'mono', cell: (n) => short(n.txid, 12, 8) },
    { label: 'Children', cls: 'num', cell: (n) => String(Object.keys(n.children ?? {}).length) },
    {
      label: 'Child txids',
      cls: 'wrap',
      cell: (n) => el('span', { class: 'mono' },
        Object.entries(n.children ?? {}).map(([vout, child], i) =>
          el('span', {}, i ? ', ' : '', `${vout}→${short(child, 6, 4)}`))),
    },
  ], tree);
}

/* -------------------------------------------------------------------- vtxo */

export function vtxoPanel(txid, vout) {
  const body = el('div', {});
  const node = el('div', {}, panelHead('VTXO', `${txid}:${vout}`), body);

  async function reload() {
    clear(body).append(card(null, skeleton()));
    try {
      const outpoint = `${txid}:${vout}`;
      const [vtxos, chain] = await Promise.all([
        indexerGet('/v1/indexer/vtxos', { outpoints: [outpoint] }).then((r) => r.vtxos ?? []),
        indexerGet(`/v1/indexer/vtxo/${encodeURIComponent(txid)}/${encodeURIComponent(vout)}/chain`)
          .then((r) => r.chain ?? []).catch(() => []),
      ]);

      clear(body);
      const v = vtxos[0];
      if (!v) {
        body.append(card(null, emptyState('VTXO not found', `The indexer has no record of ${outpoint}.`)));
        return;
      }
      body.append(...renderVtxo(v, chain));
    } catch (err) {
      clear(body).append(card(null, errorState(err)));
    }
  }

  return { node, reload };
}

function renderVtxo(v, chain) {
  const commitments = v.commitmentTxids ?? [];

  return [
    el('div', { class: 'cols-2' },
      card('VTXO', kv([
        ['Outpoint', el('span', { class: 'mono', text: `${v.outpoint?.txid}:${v.outpoint?.vout ?? 0}` })],
        ['Amount', btc(v.amount)],
        ['Created', el('span', { class: 'mono', text: ts(v.createdAt) })],
        ['Expires', el('span', { class: 'mono', text: ts(v.expiresAt) })],
        ['Depth', el('span', { class: 'mono', text: String(v.depth ?? 0) })],
        ['Script', el('span', { class: 'mono', text: v.script ?? '—' })],
      ])),
      card('Status', kv([
        ['Spent', boolBadge(v.isSpent, 'spent', 'unspent')],
        ['Swept', boolBadge(v.isSwept, 'swept', 'not swept')],
        ['Unrolled', boolBadge(v.isUnrolled, 'unrolled', 'no')],
        ['Preconfirmed', boolBadge(v.isPreconfirmed, 'preconfirmed', 'confirmed')],
        ['Spent by', v.spentBy ? el('span', { class: 'mono', text: v.spentBy }) : null],
        ['Settled by', v.settledBy ? el('span', { class: 'mono', text: v.settledBy }) : null],
        ['Ark txid', v.arkTxid ? el('span', { class: 'mono', text: v.arkTxid }) : null],
        ['Commitments', commitments.length
          ? el('span', {}, commitments.map((c, i) => el('span', {}, i ? ', ' : '',
            refLink(`#/commitment/${encodeURIComponent(c)}`, c))))
          : badge('none — this is a note', 'warn')],
      ])),
    ),
    chain.length
      ? card('Chain', table([
        { label: 'Txid', cls: 'mono', cell: (c) => short(c.txid, 12, 8) },
        { label: 'Type', cell: (c) => badge(enumLabel(c.type, 'INDEXER_CHAINED_TX_TYPE_'), 'neutral') },
        { label: 'Expires', cls: 'num', cell: (c) => timeCell(c.expiresAt) },
        {
          label: 'Spends',
          cls: 'wrap',
          cell: (c) => el('span', { class: 'mono' },
            (c.spends ?? []).map((s, i) => el('span', {}, i ? ', ' : '', short(s, 8, 6)))),
        },
      ], chain), `${chain.length} transactions back to a commitment`)
      : card('Chain', emptyState('No chain', 'The indexer returned no ancestry for this VTXO.')),
  ];
}
