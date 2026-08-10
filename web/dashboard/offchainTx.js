/*
  Offchain transaction detail.

  Reads GetOffchainTxDetails, which unlike the normal lookup does not filter by
  stage — so a transaction that failed before it was ever accepted, the case the
  regular offchain-tx read hides on purpose, is visible here.
*/

import { el, clear, num, ts, badge, stageBadge, txCell, commitmentCell } from './fmt.js';
import { adminGet } from './api.js';
import { card, kv, table, panelHead, skeleton, errorState, emptyState } from './table.js';

export function offchainTxPanel(txid) {
  const body = el('div', {});
  const node = el('div', {}, panelHead('Offchain transaction', txid), body);

  async function reload() {
    clear(body).append(card(null, skeleton()));
    try {
      const d = await adminGet(`/v1/admin/offchainTx/${encodeURIComponent(txid)}`);
      clear(body).append(...render(d));
    } catch (err) {
      clear(body).append(card(null, errorState(err)));
    }
  }

  return { node, reload };
}

function render(d) {
  const out = [];

  if (d.failed && d.failReason) {
    out.push(card('Why it failed', el('div', { class: 'card-body' },
      el('p', { class: 'panel-sub mono', text: d.failReason }),
      el('p', { class: 'hint', text: `Stopped at ${String(d.stage ?? 'unknown stage').toLowerCase().replace(/_/g, ' ')}.` }),
    )));
  }

  out.push(card('State', kv([
    ['Ark txid', txCell(d.txid, { full: true })],
    ['State', stageBadge(d)],
    ['Stage', el('span', { class: 'mono', text: String(d.stage ?? '—') })],
    ['Started', el('span', { class: 'mono', text: ts(d.startedAt) })],
    ['Ended', el('span', { class: 'mono', text: num(d.endedAt) ? ts(d.endedAt) : '—' })],
    ['Expires', el('span', { class: 'mono', text: num(d.expiresAt) ? ts(d.expiresAt) : '—' })],
    ['Root commitment', d.rootCommitmentTxid
      ? commitmentCell(d.rootCommitmentTxid, { full: true })
      : badge('not assigned — never accepted', 'fail')],
  ])));

  out.push(checkpointsCard(d));

  out.push(card('Ark transaction', d.arkTx
    ? el('div', { class: 'card-body' }, el('pre', { class: 'json-block', text: d.arkTx }))
    : emptyState('No ark transaction recorded'),
    d.arkTx ? `${d.arkTx.length} chars, base64 PSBT` : undefined));

  return out;
}

function checkpointsCard(d) {
  const txs = d.checkpointTxs ?? {};
  const commitments = d.commitmentTxids ?? {};
  const rows = Object.keys(txs);

  if (!rows.length) {
    return card('Checkpoints', emptyState(
      'No checkpoints recorded',
      'The transaction failed at request stage, before checkpoints were signed.',
    ));
  }

  const cols = [
    { label: 'Checkpoint txid', cls: 'mono', cell: (t) => txCell(t, { head: 12, tail: 8 }) },
    {
      label: 'Commitment',
      cls: 'mono',
      cell: (t) => {
        const c = commitments[t];
        if (!c) return '—';
        return el('span', {},
          commitmentCell(c),
          c === d.rootCommitmentTxid ? el('span', {}, ' ', badge('root', 'ok')) : null,
        );
      },
    },
    { label: 'Size', cls: 'num', cell: (t) => `${txs[t]?.length ?? 0} chars` },
  ];

  return card('Checkpoints', table(cols, rows), `${rows.length} checkpoints`);
}
