/*
  Batch detail.

  Accepts either a batch id or a commitment txid, because GetRoundDetails
  resolves both and operators usually have a txid from the chain rather than a
  uuid from the logs. Intents come from the persisted round, so a batch that
  failed still shows what it was trying to settle.
*/

import {
  el, clear, btcStr, btc, num, sats, short, ts, badge, stageBadge, commitmentCell, outpointCell,
} from './fmt.js';
import { adminGet } from './api.js';
import {
  card, kv, table, panelHead, skeleton, errorState, emptyState, jsonBlock,
} from './table.js';
import { decodeIcon } from './psbt.js';

/** A batch that died before the commitment tx has no txid to show. */
function commitmentOrNone(txid) {
  return txid
    ? commitmentCell(txid, { full: true })
    : badge('none — batch failed before commitment', 'fail');
}

export function batchPanel(id) {
  const body = el('div', {});
  const node = el('div', {},
    panelHead('Batch', id),
    body,
  );

  async function reload() {
    clear(body).append(card(null, skeleton()));
    const path = `/v1/admin/round/${encodeURIComponent(id)}`;

    // Each read loads the whole round server-side, so the page paints on the
    // details and the intents card fills itself in later. Intents may fail
    // alone: a batch that died before registration has details but none.
    const slot = el('div', {}, card('Intents', skeleton()));
    const pending = adminGet(`${path}/intents`)
      .then((r) => r.intents ?? [])
      .catch(() => null);

    try {
      clear(body).append(...render(await adminGet(path), slot));
    } catch (err) {
      clear(body).append(card(null, errorState(err)));
      return;
    }

    // Not awaited: navigating away should not wait on it.
    void pending.then((intents) => clear(slot).append(intentsCard(intents)));
  }

  return { node, reload };
}

function render(d, intentsSlot) {
  const out = [heroCard(d)];

  if (d.failed && d.failReason) {
    out.push(card('Why it failed', el('div', { class: 'card-body' },
      el('p', { class: 'panel-sub mono', text: d.failReason }),
      el('p', { class: 'hint', text: `Recorded ${ts(d.endedAt)}.` }),
    )));
  }

  out.push(el('div', { class: 'cols-2' },
    card('State', kv([
      ['Batch id', el('span', { class: 'mono', text: d.roundId })],
      ['State', stageBadge(d)],
      ['Stage', el('span', { class: 'mono', text: String(d.stage ?? '—') })],
      ['Swept', d.swept ? badge('swept', 'ok') : badge('not swept', 'neutral')],
      ['Started', el('span', { class: 'mono', text: ts(d.startedAt) })],
      ['Ended', el('span', { class: 'mono', text: num(d.endedAt) ? ts(d.endedAt) : '—' })],
      ['Intents', el('span', { class: 'mono', text: sats(d.totalIntents) })],
      ['Commitment txid', commitmentOrNone(d.commitmentTxid)],
    ])),
    card('Amounts', kv([
      ['Forfeited', btcStr(d.forfeitedAmount)],
      ['Into VTXOs', btcStr(d.totalVtxosAmount)],
      ['Exited onchain', btcStr(d.totalExitAmount)],
      ['Fees collected', btcStr(d.totalFeeAmount)],
      ['Input VTXOs', el('span', { class: 'mono', text: String(d.inputsVtxos?.length ?? 0) })],
      ['Output VTXOs', el('span', { class: 'mono', text: String(d.outputsVtxos?.length ?? 0) })],
    ])),
  ));

  out.push(intentsSlot);

  if (d.exitAddresses?.length) {
    out.push(card('Exit addresses', table(
      [{ label: 'Address', cls: 'mono', cell: (a) => a }],
      d.exitAddresses,
    ), `${d.exitAddresses.length} onchain receivers`));
  }

  out.push(el('div', { class: 'cols-2' },
    outpointsCard('Input VTXOs', d.inputsVtxos, 'Nothing spent into this batch.'),
    outpointsCard('Output VTXOs', d.outputsVtxos, 'No leaf VTXOs: no tree.'),
  ));

  return out;
}

/** What an operator in a hurry came for: the liquidity, and the txid. */
function heroCard(d) {
  const swept = d.swept
    ? badge('swept', 'ok')
    : badge('unswept', d.failed ? 'neutral' : 'warn');

  return card(null, el('div', { class: 'hero' },
    el('div', { class: 'hero-main' },
      el('p', { class: 'eyebrow', text: 'Locked up by this batch' }),
      btcStr(d.totalVtxosAmount, { large: true }),
      el('p', { class: 'hint', text: 'Value in the vtxo tree, returned by the sweep.' }),
    ),
    el('div', { class: 'hero-side' },
      el('p', { class: 'eyebrow', text: 'Commitment tx' }),
      commitmentOrNone(d.commitmentTxid),
      el('div', { class: 'hero-badges' }, d.failed ? stageBadge(d) : swept),
    ),
  ));
}

function intentsCard(intents) {
  if (intents === null) {
    return card('Intents', emptyState('Intents unavailable', 'Most likely failed before registration.'));
  }
  if (!intents.length) {
    return card('Intents', emptyState('No intents registered'));
  }

  const cols = [
    { label: 'Intent', cls: 'mono', cell: (r) => short(r.id, 10, 6) },
    { label: 'Inputs', cls: 'num', cell: (r) => String(r.inputs?.length ?? 0) },
    { label: 'Receivers', cls: 'num', cell: (r) => String(r.receivers?.length ?? 0) },
    {
      label: 'In',
      cls: 'num',
      cell: (r) => btc((r.inputs ?? []).reduce((s, i) => s + num(i.amount), 0)),
    },
    {
      label: 'Out',
      cls: 'num',
      cell: (r) => btc((r.receivers ?? []).reduce((s, o) => s + num(o.amount), 0)),
    },
    {
      label: 'Destinations',
      cls: 'wrap',
      cell: (r) => el('span', { class: 'mono' },
        (r.receivers ?? []).map((o, i) => el('span', {},
          i ? ', ' : '',
          o.onchainAddress ? short(o.onchainAddress, 10, 6) : short(o.vtxoScript, 10, 6),
        ))),
    },
    // In full, not behind a disclosure: often the reason for opening the batch.
    { label: 'Message', cls: 'wrap', cell: (r) => jsonBlock(r.intent?.message) },
    { label: 'Proof', cell: (r) => decodeIcon(r.intent?.proof, 'Intent proof') },
  ];

  return card('Intents', table(cols, intents), intentsNote(intents));
}

/** An arkd predating intent proofs sends no `intent` at all. Say so, don't dash. */
function intentsNote(intents) {
  if (intents.every((i) => !i.intent?.message && !i.intent?.proof)) {
    return 'this arkd returns no intent messages or proofs';
  }
  return 'boarding inputs and cosigner keys are not persisted with the intent';
}

function outpointsCard(title, list, emptyHint) {
  if (!list?.length) return card(title, emptyState('None', emptyHint));
  return card(title, table(
    [{ label: 'Outpoint', cls: 'mono', cell: (o) => outpointCell(...o.split(':'), { full: true }) }],
    list,
  ), `${list.length} outpoints`);
}
