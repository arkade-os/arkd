/*
  Descriptors for every panel that is just "GET a URL, show a table".

  Adding an endpoint here costs a few lines. Anything that needs real logic
  lives in solvency.js, batch.js, or offchainTx.js instead.
*/

import {
  el, btc, btcStr, sats, num, short, ts, dur,
  timeCell, badge, boolBadge, stageBadge, enumLabel, refLink,
  dateToUnix, unixToDate,
} from './fmt.js';
import { listPanel, objectPanel, kv, card, table } from './table.js';

const DAY = 86400;

/** Default date-range filters, spanning the last `days` days. */
function rangeFilters(days = 7) {
  const now = Math.floor(Date.now() / 1000);
  return [
    { name: 'after', label: 'From', type: 'date', value: unixToDate(now - days * DAY) },
    { name: 'before', label: 'To', type: 'date', value: unixToDate(now + DAY) },
  ];
}

function rangeParams(v) {
  return {
    after: dateToUnix(v.after),
    before: dateToUnix(v.before, true),
  };
}

/* ----------------------------------------------------------------- batches */

export const batches = () => listPanel({
  title: 'Batches',
  sub: 'Settlement batches in the selected window, most recent first. Failed batches carry the reason arkd recorded when it gave up.',
  cardTitle: 'Batches',
  source: 'admin',
  path: '/v1/admin/rounds',
  key: 'summaries',
  empty: 'No batches in this window',
  emptyHint: 'Widen the date range, or clear the failed-only filter.',
  filters: [
    ...rangeFilters(7),
    { name: 'onlyFailed', label: 'Failed only', type: 'check', value: false },
    { name: 'withCompleted', label: 'Include completed', type: 'check', value: true },
    { name: 'withFailed', label: 'Include failed', type: 'check', value: true },
    { name: 'limit', label: 'Limit', type: 'number', value: 100 },
  ],
  params: (v) => ({
    ...rangeParams(v),
    only_failed: v.onlyFailed,
    with_completed: v.withCompleted,
    with_failed: v.withFailed,
    limit: num(v.limit),
  }),
  cols: [
    { label: 'Batch', cls: 'mono', cell: (r) => refLink(`#/batch/${encodeURIComponent(r.roundId)}`, r.roundId) },
    { label: 'State', cell: (r) => stageBadge(r) },
    { label: 'Started', cls: 'num', cell: (r) => timeCell(r.startedAt) },
    { label: 'Ended', cls: 'num', cell: (r) => timeCell(r.endedAt) },
    { label: 'Intents', cls: 'num', cell: (r) => sats(r.totalIntents) },
    {
      label: 'Commitment',
      cls: 'mono',
      cell: (r) => r.commitmentTxid
        ? refLink(`#/commitment/${encodeURIComponent(r.commitmentTxid)}`, r.commitmentTxid)
        : '—',
    },
    { label: 'Fail reason', cls: 'wrap', cell: (r) => r.failReason || '—' },
  ],
});

export const expiredBatches = () => listPanel({
  title: 'Expired batches',
  sub: 'Batches whose outputs passed their expiry but were never swept. Each one is liability the server still carries and funds it has not reclaimed.',
  cardTitle: 'Expired, unswept',
  source: 'admin',
  path: '/v1/admin/rounds/expired',
  key: 'rounds',
  empty: 'Nothing expired and unswept',
  emptyHint: 'Every expired batch has been swept.',
  cols: [
    { label: 'Batch', cls: 'mono', cell: (r) => refLink(`#/batch/${encodeURIComponent(r.roundId)}`, r.roundId) },
    { label: 'Commitment', cls: 'mono', cell: (r) => refLink(`#/commitment/${encodeURIComponent(r.commitmentTxid)}`, r.commitmentTxid) },
    { label: 'Expired', cls: 'num', cell: (r) => timeCell(r.expiredAt) },
    { label: 'Overdue by', cls: 'num', cell: (r) => dur(Math.max(0, Math.floor(Date.now() / 1000) - num(r.expiredAt))) },
  ],
});

export const scheduledSweeps = () => listPanel({
  title: 'Scheduled sweeps',
  sub: 'Batches awaiting a sweep, soonest due first, with the unswept value each still carries.',
  cardTitle: 'Scheduled sweeps',
  source: 'admin',
  path: '/v1/admin/sweeps',
  key: 'sweeps',
  empty: 'No sweeps scheduled',
  emptyHint: 'Every batch with a vtxo tree has been swept.',
  filters: [
    { name: 'limit', label: 'Limit', type: 'number', value: 100 },
  ],
  params: (v) => ({ limit: num(v.limit) }),
  note: (rows) => {
    const total = rows.reduce((sum, r) => sum + num(r.totalAmount), 0);
    return `${rows.length} batches · ${sats(total)} sats at stake`;
  },
  cols: [
    { label: 'Batch', cls: 'mono', cell: (r) => refLink(`#/batch/${encodeURIComponent(r.roundId)}`, r.roundId) },
    {
      label: 'Commitment',
      cls: 'mono',
      cell: (r) => (r.commitmentTxid
        ? refLink(`#/commitment/${encodeURIComponent(r.commitmentTxid)}`, r.commitmentTxid)
        : '—'),
    },
    { label: 'Due', cls: 'num', cell: (r) => timeCell(r.sweepAt) },
    {
      label: 'Overdue by',
      cls: 'num',
      cell: (r) => {
        const overdue = Math.floor(Date.now() / 1000) - num(r.sweepAt);
        return overdue > 0 ? dur(overdue) : '—';
      },
    },
    { label: 'Unswept vtxos', cls: 'num', cell: (r) => sats(r.vtxoCount) },
    { label: 'At stake', cls: 'num', cell: (r) => btc(r.totalAmount) },
  ],
  // Pending work, not history: the most overdue sweep is the one to look at first.
  sort: (a, b) => num(a.sweepAt) - num(b.sweepAt),
});

/* ------------------------------------------------------------- offchain txs */

export const offchainTxs = () => listPanel({
  title: 'Offchain transactions',
  sub: 'Ark transactions in the selected window. Failures are kept with their reason, including the ones that never reached the accepted stage.',
  cardTitle: 'Offchain transactions',
  source: 'admin',
  path: '/v1/admin/offchainTxs',
  key: 'txs',
  empty: 'No offchain transactions in this window',
  emptyHint: 'Widen the date range, or clear the failed-only filter.',
  filters: [
    ...rangeFilters(1),
    { name: 'onlyFailed', label: 'Failed only', type: 'check', value: false },
    { name: 'onlyCompleted', label: 'Finalized only', type: 'check', value: false },
    { name: 'limit', label: 'Limit', type: 'number', value: 100 },
  ],
  params: (v) => ({
    ...rangeParams(v),
    only_failed: v.onlyFailed,
    only_completed: v.onlyCompleted,
    limit: num(v.limit),
  }),
  cols: [
    { label: 'Ark txid', cls: 'mono', cell: (r) => refLink(`#/offchain/${encodeURIComponent(r.txid)}`, r.txid) },
    { label: 'State', cell: (r) => stageBadge(r) },
    { label: 'Started', cls: 'num', cell: (r) => timeCell(r.startedAt) },
    { label: 'Ended', cls: 'num', cell: (r) => timeCell(r.endedAt) },
    { label: 'Checkpoints', cls: 'num', cell: (r) => sats(r.totalCheckpoints) },
    {
      label: 'Root commitment',
      cls: 'mono',
      cell: (r) => r.rootCommitmentTxid
        ? refLink(`#/commitment/${encodeURIComponent(r.rootCommitmentTxid)}`, r.rootCommitmentTxid)
        : '—',
    },
    { label: 'Fail reason', cls: 'wrap', cell: (r) => r.failReason || '—' },
  ],
});

/* ----------------------------------------------------------------- intents */

export const intentQueue = () => listPanel({
  title: 'Intent queue',
  sub: 'Intents waiting for the next batch. This is live queue state, so it empties as batches start.',
  cardTitle: 'Queued intents',
  source: 'admin',
  path: '/v1/admin/intents',
  key: 'intents',
  empty: 'The queue is empty',
  emptyHint: 'Nothing is waiting for the next batch.',
  cols: [
    { label: 'Intent', cls: 'mono', cell: (r) => short(r.id, 10, 6) },
    { label: 'Registered', cls: 'num', cell: (r) => timeCell(r.createdAt) },
    { label: 'Inputs', cls: 'num', cell: (r) => String(r.inputs?.length ?? 0) },
    { label: 'Boarding', cls: 'num', cell: (r) => String(r.boardingInputs?.length ?? 0) },
    { label: 'Receivers', cls: 'num', cell: (r) => String(r.receivers?.length ?? 0) },
    {
      label: 'In',
      cls: 'num',
      cell: (r) => btc([...(r.inputs ?? []), ...(r.boardingInputs ?? [])]
        .reduce((sum, i) => sum + num(i.amount), 0)),
    },
    {
      label: 'Out',
      cls: 'num',
      cell: (r) => btc((r.receivers ?? []).reduce((sum, o) => sum + num(o.amount), 0)),
    },
    { label: 'Cosigners', cls: 'num', cell: (r) => String(r.cosignersPublicKeys?.length ?? 0) },
  ],
});

/* -------------------------------------------------------------- convictions */

const convictionCols = [
  { label: 'Conviction', cls: 'mono', cell: (r) => short(r.id, 10, 6) },
  { label: 'Crime', cell: (r) => badge(enumLabel(r.crimeType, 'CRIME_TYPE_'), r.pardoned ? 'neutral' : 'fail') },
  { label: 'Status', cell: (r) => (r.pardoned ? badge('pardoned', 'ok') : badge('active', 'warn')) },
  { label: 'Created', cls: 'num', cell: (r) => timeCell(r.createdAt) },
  { label: 'Expires', cls: 'num', cell: (r) => (num(r.expiresAt) ? timeCell(r.expiresAt) : badge('never', 'neutral')) },
  { label: 'Script', cls: 'mono', cell: (r) => short(r.script, 10, 8) },
  {
    label: 'Batch',
    cls: 'mono',
    cell: (r) => (r.roundId && r.roundId !== 'manual-ban'
      ? refLink(`#/batch/${encodeURIComponent(r.roundId)}`, r.roundId)
      : (r.roundId || '—')),
  },
  { label: 'Reason', cls: 'wrap', cell: (r) => r.reason || '—' },
];

export const convictions = () => listPanel({
  title: 'Convictions',
  sub: 'Scripts banned for misbehaving during a batch. Search a window, a batch, or a single script.',
  cardTitle: 'Convictions',
  source: 'admin',
  key: 'convictions',
  empty: 'No convictions found',
  emptyHint: 'Nothing matched. Try a wider window or a different batch.',
  filters: [
    {
      name: 'mode',
      label: 'Search by',
      type: 'select',
      value: 'range',
      options: [
        { value: 'range', label: 'Time range' },
        { value: 'round', label: 'Batch id' },
        { value: 'script', label: 'Script (active only)' },
        { value: 'ids', label: 'Conviction ids' },
      ],
    },
    ...rangeFilters(30),
    { name: 'needle', label: 'Batch id / script / ids', type: 'text', grow: true, placeholder: 'paste a batch id, script hex, or comma-separated ids' },
  ],
  requires: (v) => (v.mode !== 'range' && !v.needle.trim()
    ? 'Enter a value to search for.'
    : null),
  path: (v) => {
    const needle = encodeURIComponent(v.needle.trim());
    if (v.mode === 'round') return `/v1/admin/convictionsByRound/${needle}`;
    if (v.mode === 'script') return `/v1/admin/convictionsByScript/${needle}`;
    if (v.mode === 'ids') return `/v1/admin/convictions/${encodeURIComponent(v.needle.trim().replace(/\s/g, ''))}`;
    return '/v1/admin/convictionsInRange';
  },
  params: (v) => (v.mode === 'range'
    ? { from: dateToUnix(v.after), to: dateToUnix(v.before, true) }
    : undefined),
  cols: convictionCols,
});

/* ------------------------------------------------------------------ wallet */

export const wallet = (opts = {}) => objectPanel({
  bare: opts.bare,
  title: 'Wallet',
  sub: 'Operator wallet state and the UTXO set backing the main account. Read-only: this console cannot unlock, derive, or withdraw.',
  source: 'admin',
  path: '/v1/admin/wallet/balance',
  render: (balance) => card('Balance', kv([
    ['Main available', btcStr(balance?.mainAccount?.available)],
    ['Main locked', btcStr(balance?.mainAccount?.locked)],
    ['Connectors available', btcStr(balance?.connectorsAccount?.available)],
    ['Connectors locked', btcStr(balance?.connectorsAccount?.locked)],
  ])),
});

export const walletUtxos = (opts = {}) => listPanel({
  bare: opts.bare,
  title: 'Wallet UTXOs',
  sub: 'The UTXO set of the main account, as arkd sees it.',
  cardTitle: 'Main account UTXOs',
  source: 'admin',
  path: '/v1/admin/wallet/utxos',
  key: 'utxos',
  empty: 'No UTXOs in the main account',
  note: (rows) => {
    const total = rows.reduce((sum, u) => sum + num(u.value), 0);
    return `${rows.length} utxos · ${sats(total)} sats`;
  },
  cols: [
    { label: 'Outpoint', cls: 'mono', cell: (r) => `${short(r.txid)}:${r.vout ?? 0}` },
    { label: 'Value', cls: 'num', cell: (r) => btc(r.value) },
    { label: 'Confirmations', cls: 'num', cell: (r) => sats(r.confirmations) },
    { label: 'Locked', cell: (r) => boolBadge(r.locked, 'locked', 'free') },
    { label: 'Address', cls: 'mono', cell: (r) => short(r.address, 12, 8) },
    { label: 'Script', cls: 'mono', cell: (r) => short(r.script, 10, 6) },
  ],
});

/* ------------------------------------------------------------------ config */

export const settings = (opts = {}) => objectPanel({
  bare: opts.bare,
  title: 'Settings',
  sub: 'Live server configuration. Change these with the arkd CLI — this console never writes.',
  source: 'admin',
  path: '/v1/admin/settings',
  pick: (r) => r.settings ?? {},
  render: (s) => el('div', { class: 'cols-2' },
    card('Timing', kv([
      ['Session duration', durCell(s.sessionDuration)],
      ['Batch trigger', s.batchTrigger ? el('span', { class: 'mono', text: s.batchTrigger }) : null],
      ['VTXO tree expiry', durCell(s.vtxoTreeExpiry)],
      ['Unrolled VTXO min expiry margin', durCell(s.unrolledVtxoMinExpiryMargin)],
      ['Settlement min expiry gap', durCell(s.settlementMinExpiryGap)],
    ])),
    card('Exit delays', kv([
      ['Unilateral exit', durCell(s.unilateralExitDelay)],
      ['Public unilateral exit', durCell(s.publicUnilateralExitDelay)],
      ['Checkpoint exit', durCell(s.checkpointExitDelay)],
      ['Boarding exit', durCell(s.boardingExitDelay)],
    ])),
    card('Amounts', kv([
      ['VTXO min', amountCell(s.vtxoMinAmount)],
      ['VTXO max', amountCell(s.vtxoMaxAmount)],
      ['UTXO min', amountCell(s.utxoMinAmount)],
      ['UTXO max', amountCell(s.utxoMaxAmount)],
    ])),
    card('Participation', kv([
      ['Min participants', numCell(s.roundMinParticipantsCount)],
      ['Max participants', numCell(s.roundMaxParticipantsCount)],
      ['Ban threshold', numCell(s.banThreshold)],
      ['Ban duration', durCell(s.banDuration)],
    ])),
    card('Transaction limits', kv([
      ['Max tx weight', numCell(s.maxTxWeight)],
      ['Max OP_RETURN outputs', numCell(s.maxOpReturnOutputs)],
      ['Asset tx max weight ratio', s.assetTxMaxWeightRatio != null ? el('span', { text: String(s.assetTxMaxWeightRatio) }) : null],
      ['No-CSV validation cutoff', s.vtxoNoCsvValidationCutoffDate ? el('span', { text: s.vtxoNoCsvValidationCutoffDate }) : null],
    ])),
    card('Protocol headers', kv([
      ['Note URI prefix', s.noteUriPrefix ? el('span', { class: 'mono', text: s.noteUriPrefix }) : null],
      ['Build version header', s.buildVersionHeader ? el('span', { class: 'mono', text: s.buildVersionHeader }) : null],
      ['Build version required', boolBadge(s.buildVersionHeaderRequired, 'required', 'optional')],
      ['Digest header required', boolBadge(s.digestHeaderRequired, 'required', 'optional')],
      ['Updated', s.updatedAt ? el('span', { class: 'mono', text: s.updatedAt }) : null],
    ])),
  ),
});

export const scheduledSession = (opts = {}) => objectPanel({
  bare: opts.bare,
  title: 'Scheduled session',
  sub: 'The recurring batch window, when one is configured.',
  source: 'admin',
  path: '/v1/admin/scheduledSession',
  pick: (r) => r.config ?? null,
  render: (c) => (c && Object.keys(c).length
    ? card('Scheduled session', kv([
      ['Start', c.startTime ? el('span', { class: 'mono', text: c.startTime }) : null],
      ['End', c.endTime ? el('span', { class: 'mono', text: c.endTime }) : null],
      ['Period', durCell(c.period)],
      ['Duration', durCell(c.duration)],
      ['Min participants', numCell(c.roundMinParticipantsCount)],
      ['Max participants', numCell(c.roundMaxParticipantsCount)],
    ]))
    : card('Scheduled session', el('div', { class: 'state' },
      el('p', { class: 'state-title', text: 'No scheduled session' }),
      el('p', { text: 'Batches run on the normal trigger.' }),
    ))),
});

export const fees = (opts = {}) => objectPanel({
  bare: opts.bare,
  title: 'Fees',
  sub: 'The per-input and per-output fees charged on intents, and what the server has collected over a window.',
  source: 'admin',
  path: '/v1/admin/intentFees',
  pick: (r) => r.fees ?? {},
  render: (f) => card('Intent fees', kv([
    ['Offchain input', btcStr(f.offchainInputFee)],
    ['Onchain input', btcStr(f.onchainInputFee)],
    ['Offchain output', btcStr(f.offchainOutputFee)],
    ['Onchain output', btcStr(f.onchainOutputFee)],
  ])),
});

export const collectedFees = (opts = {}) => objectPanel({
  bare: opts.bare,
  title: 'Collected fees',
  sub: 'Fees the operator collected from batches that finalized in the selected window.',
  source: 'admin',
  path: '/v1/admin/fees/collected',
  filters: rangeFilters(30),
  params: rangeParams,
  render: (r) => card('Collected', el('div', { class: 'liab' },
    el('p', { class: 'eyebrow', text: 'Collected in window' }),
    btc(r.collectedFees, { large: true }),
    el('p', { class: 'hint', text: `${sats(r.collectedFees)} sats` }),
  )),
});

/* ------------------------------------------------------------ vtxo lookup */

export const vtxoLookup = () => listPanel({
  title: 'VTXO lookup',
  sub: 'Query the public indexer by script or by outpoint. No macaroon is used for these — the indexer is unauthenticated.',
  cardTitle: 'VTXOs',
  source: 'indexer',
  path: '/v1/indexer/vtxos',
  key: 'vtxos',
  empty: 'No VTXOs matched',
  emptyHint: 'Check the script hex or the txid:vout you entered.',
  filters: [
    {
      name: 'mode',
      label: 'Search by',
      type: 'select',
      value: 'scripts',
      options: [
        { value: 'scripts', label: 'Script' },
        { value: 'outpoints', label: 'Outpoint' },
      ],
    },
    { name: 'needle', label: 'Script hex or txid:vout', type: 'text', grow: true, placeholder: '5120… or abcd…:0' },
    { name: 'spendableOnly', label: 'Spendable only', type: 'check', value: false },
    { name: 'spentOnly', label: 'Spent only', type: 'check', value: false },
    { name: 'recoverableOnly', label: 'Recoverable only', type: 'check', value: false },
  ],
  requires: (v) => (v.needle.trim() ? null : 'Enter a script or an outpoint to search.'),
  params: (v) => ({
    [v.mode]: v.needle.trim().split(/[\s,]+/).filter(Boolean),
    spendable_only: v.mode === 'scripts' ? v.spendableOnly : undefined,
    spent_only: v.mode === 'scripts' ? v.spentOnly : undefined,
    recoverable_only: v.mode === 'scripts' ? v.recoverableOnly : undefined,
  }),
  cols: [
    {
      label: 'Outpoint',
      cls: 'mono',
      cell: (r) => refLink(
        `#/vtxo/${encodeURIComponent(r.outpoint?.txid ?? '')}/${r.outpoint?.vout ?? 0}`,
        `${short(r.outpoint?.txid)}:${r.outpoint?.vout ?? 0}`,
        { full: true },
      ),
    },
    { label: 'Amount', cls: 'num', cell: (r) => btc(r.amount) },
    {
      label: 'State',
      cell: (r) => {
        if (r.isSpent) return badge('spent', 'neutral');
        if (r.isSwept) return badge('swept', 'ok');
        if (r.isUnrolled) return badge('unrolled', 'warn');
        if (r.isPreconfirmed) return badge('preconfirmed', 'warn');
        return badge('spendable', 'ok');
      },
    },
    { label: 'Created', cls: 'num', cell: (r) => timeCell(r.createdAt) },
    { label: 'Expires', cls: 'num', cell: (r) => timeCell(r.expiresAt) },
    { label: 'Depth', cls: 'num', cell: (r) => String(r.depth ?? 0) },
    {
      label: 'Commitments',
      cls: 'mono',
      cell: (r) => {
        const list = r.commitmentTxids ?? [];
        if (!list.length) return badge('note', 'warn');
        return refLink(`#/commitment/${encodeURIComponent(list[0])}`, list[0]);
      },
    },
    { label: 'Spent by', cls: 'mono', cell: (r) => (r.spentBy ? short(r.spentBy) : '—') },
  ],
});

/* ----------------------------------------------------------------- helpers */

function durCell(v) {
  return v === null || v === undefined ? null : el('span', { title: `${sats(v)} seconds`, text: dur(v) });
}

function numCell(v) {
  return v === null || v === undefined ? null : el('span', { text: sats(v) });
}

function amountCell(v) {
  if (v === null || v === undefined) return null;
  if (num(v) < 0) return badge('unlimited', 'neutral');
  return btc(v);
}
