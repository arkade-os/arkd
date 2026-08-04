/*
  Batch detail.

  Accepts either a batch id or a commitment txid, because GetRoundDetails
  resolves both and operators usually have a txid from the chain rather than a
  uuid from the logs. Intents come from the persisted round, so a batch that
  failed still shows what it was trying to settle.
*/

import { el, clear, btcStr, btc, num, sats, short, ts, timeCell, badge, stageBadge, refLink } from './fmt.js';
import { adminGet } from './api.js';
import { card, kv, table, panelHead, skeleton, errorState, emptyState } from './table.js';
import { hasIndexer } from './api.js';

export function batchPanel(id) {
  const body = el('div', {});
  const node = el('div', {},
    panelHead('Batch', id),
    body,
  );

  async function reload() {
    clear(body).append(card(null, skeleton()));
    try {
      const path = `/v1/admin/round/${encodeURIComponent(id)}`;
      // Intents are a separate read and are allowed to fail independently — a
      // batch that died before registration has details but no intents.
      const [details, intents] = await Promise.all([
        adminGet(path),
        adminGet(`${path}/intents`).then((r) => r.intents ?? []).catch(() => null),
      ]);
      clear(body).append(...render(details, intents));
    } catch (err) {
      clear(body).append(card(null, errorState(err)));
    }
  }

  return { node, reload };
}

function render(d, intents) {
  const out = [];

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
      ['Commitment txid', d.commitmentTxid
        ? (hasIndexer()
          ? refLink(`#/commitment/${encodeURIComponent(d.commitmentTxid)}`, d.commitmentTxid, { full: true })
          : el('span', { class: 'mono', text: d.commitmentTxid }))
        : badge('none — batch failed before commitment', 'fail')],
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

  out.push(intentsCard(intents));

  if (d.exitAddresses?.length) {
    out.push(card('Exit addresses', table(
      [{ label: 'Address', cls: 'mono', cell: (a) => a }],
      d.exitAddresses,
    ), `${d.exitAddresses.length} onchain receivers`));
  }

  out.push(el('div', { class: 'cols-2' },
    outpointsCard('Input VTXOs', d.inputsVtxos, 'Nothing was spent into this batch.'),
    outpointsCard('Output VTXOs', d.outputsVtxos, 'No leaf VTXOs — the batch never produced a tree.'),
  ));

  return out;
}

function intentsCard(intents) {
  if (intents === null) {
    return card('Intents', emptyState(
      'Intents unavailable',
      'arkd did not return intents for this batch. It most likely failed before registration.',
    ));
  }
  if (!intents.length) {
    return card('Intents', emptyState(
      'No intents registered',
      'The batch failed before any intent was registered, or every participant dropped out.',
    ));
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
  ];

  return card('Intents', table(cols, intents),
    'boarding inputs and cosigner keys are not persisted with the intent');
}

function outpointsCard(title, list, emptyHint) {
  if (!list?.length) return card(title, emptyState('None', emptyHint));
  return card(title, table(
    [{ label: 'Outpoint', cls: 'mono', cell: (o) => o }],
    list,
  ), `${list.length} outpoints`);
}
