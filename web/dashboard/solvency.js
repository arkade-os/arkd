/*
  Overview — the solvency view.

  This is the `arkd liquidity-report` composition (5 calls) plus three things the
  CLI report cannot tell you:

    - The overdue bucket. VTXOs already past expires_at but not yet swept fall
      out of both halves of the report: the expiring query needs
      expires_at > after, and the recoverable query needs swept = true. They are
      real liability and the CLI shows them nowhere. Querying after=1 (rather
      than 0, which the handler coerces to now) surfaces them.
    - Coverage. Liability next to the wallet balance that has to back it.
    - The derived totals an operator otherwise works out by hand.
*/

import { el, clear, btc, num, sats } from './fmt.js';
import { adminGet } from './api.js';
import { card, table, panelHead, skeleton, errorState, emptyState } from './table.js';

const DAY = 86400;

/* Left to right: overdue sits before "now" where it should not exist. */
const BUCKETS = [
  { id: 'overdue',     label: 'Past expiry',  axis: 'past',   cls: 'overdue',     swatch: 'var(--oxide)' },
  { id: 'd1',          label: 'Under 1 day',  axis: 'now',    cls: 'd1',          swatch: 'var(--amber)' },
  { id: 'd2',          label: '1 – 2 days',   axis: null,     cls: 'd2',          swatch: '#b9793c' },
  { id: 'd3',          label: '2 – 3 days',   axis: null,     cls: 'd3',          swatch: '#8f6134' },
  { id: 'later',       label: 'Over 3 days',  axis: '3d+',    cls: 'later',       swatch: 'var(--gold-dim)' },
  { id: 'recoverable', label: 'Recoverable',  axis: 'swept',  cls: 'recoverable', swatch: 'var(--teal-dim)' },
];

export function solvencyPanel() {
  const body = el('div', {});
  const node = el('div', {},
    panelHead('Overview', 'Liability, when it unlocks, and what covers it.'),
    body,
  );

  async function reload() {
    clear(body).append(card(null, skeleton()));

    // The sweep schedule is the slow read: it is unbounded and grows with the
    // number of unswept batches. Fire it now, paint without it, fill in after.
    const slot = el('div', {}, card('Sweep inflow', skeleton()));
    const pending = adminGet('/v1/admin/sweeps', { limit: 0 })
      .then((r) => r.sweeps ?? [])
      .catch(() => null);

    let d;
    try {
      d = await load();
    } catch (err) {
      clear(body).append(card(null, errorState(err)));
      return;
    }
    clear(body).append(liabilityCard(d), slot, tiles(d), caveats());

    // Not awaited: navigating away should not wait on it.
    void pending.then((sweeps) => clear(slot).append(sweepsCard(sweeps, d.unswept)));
  }

  return { node, reload };
}

/* -------------------------------------------------------------------- load */

async function load() {
  const now = Math.floor(Date.now() / 1000);

  // after=1 rather than 0: the handler treats after<=0 as "now", which would
  // both hide the overdue rows and make after >= before an invalid range.
  const expiring = (after, before) =>
    adminGet('/v1/admin/liquidity/expiring', { after, before }).then((r) => num(r.amount));

  // The liability reads are required: without them the panel has nothing to say.
  // Everything else is best-effort, so a locked wallet or an older server that
  // lacks GetFeeRate degrades one tile instead of blanking the whole overview.
  let walletError = null;

  const [overdue, d1, d2, d3, later, recoverable, balance, status, feeRate] =
    await Promise.all([
      expiring(1, now),
      expiring(now, now + DAY),
      expiring(now + DAY, now + 2 * DAY),
      expiring(now + 2 * DAY, now + 3 * DAY),
      expiring(now + 3 * DAY, 0),
      adminGet('/v1/admin/liquidity/recoverable').then((r) => num(r.amount)),
      // The balance is the only optional read whose failure is worth naming: it
      // drives the coverage figure.
      adminGet('/v1/admin/wallet/balance').catch((err) => {
        walletError = err?.message ?? 'unavailable';
        return null;
      }),
      adminGet('/v1/admin/wallet/status').catch(() => null),
      adminGet('/v1/admin/feeRate').catch(() => null),
    ]);

  const amounts = { overdue, d1, d2, d3, later, recoverable };

  // Every bucket is swept = false / spent = false and the windows are contiguous,
  // so the buckets are disjoint and safe to sum.
  const unswept = overdue + d1 + d2 + d3 + later;
  const total = unswept + recoverable;

  // Overdue is already past due, so it belongs in the 72h figure.
  const due72h = recoverable + overdue + d1 + d2 + d3;

  const wallet = {
    mainAvailable: btcToSats(balance?.mainAccount?.available),
    mainLocked: btcToSats(balance?.mainAccount?.locked),
    connAvailable: btcToSats(balance?.connectorsAccount?.available),
    connLocked: btcToSats(balance?.connectorsAccount?.locked),
  };
  wallet.total = wallet.mainAvailable + wallet.mainLocked + wallet.connAvailable + wallet.connLocked;
  wallet.known = balance !== null;

  return { amounts, unswept, total, due72h, wallet, status, feeRate, walletError };
}

function btcToSats(s) {
  const n = Number(String(s ?? '0'));
  return Number.isFinite(n) ? Math.round(n * 1e8) : 0;
}

/* ------------------------------------------------------------------ render */

// Windows are cumulative from now: a sweep falls in the first one it fits.
const SWEEP_WINDOWS = [
  { label: 'Past due', within: 0 },
  { label: 'Within 24h', within: DAY },
  { label: '1 – 3 days', within: 3 * DAY },
  { label: '3 – 7 days', within: 7 * DAY },
  { label: 'Later', within: Infinity },
];

/**
 * Unswept leaf value from the sweep schedule: a batch whose leaves were spent
 * forward reports nothing even though its output still returns coins. A floor.
 */
function sweepsCard(sweeps, locked) {
  if (sweeps === null) {
    return card('Sweep inflow', emptyState('Sweep schedule unavailable'));
  }
  if (!sweeps.length) {
    return card('Sweep inflow', emptyState('Nothing scheduled'));
  }

  const now = Math.floor(Date.now() / 1000);
  const rows = SWEEP_WINDOWS.map((w) => ({ ...w, amount: 0, batches: 0 }));
  let blind = 0;

  for (const s of sweeps) {
    const delta = num(s.sweepAt) - now;
    const row = rows.find((w) => delta <= w.within);
    row.amount += num(s.totalAmount);
    row.batches += 1;
    if (!num(s.vtxoCount)) blind += 1;
  }

  let running = 0;
  for (const row of rows) {
    running += row.amount;
    row.cumulative = running;
  }

  return card('Sweep inflow', el('div', {},
    table([
      { label: 'When', cell: (r) => r.label },
      { label: 'Batches', cls: 'num', cell: (r) => String(r.batches) },
      { label: 'Reclaimed', cls: 'num', cell: (r) => btc(r.amount) },
      { label: 'Running total', cls: 'num', cell: (r) => btc(r.cumulative) },
    ], rows.filter((r) => r.batches)),
    el('div', { class: 'card-body' },
      el('p', { class: 'hint', text: 'Sweep date = batch end + tree expiry, an estimate: the sweeper goes by the onchain locktime. Amount = unspent, unswept leaves of that batch.' }),
      blind ? el('p', { class: 'hint', text: `${blind} of ${sweeps.length} batches have no unspent leaves left: their value was spent forward into preconfirmed VTXOs, which still sit in the same batch output but are not counted here. The totals are a floor.` }) : null,
    ),
  // Inflow counts unrolled leaves that the locked figure drops, so it can top it.
  ), running <= locked
    ? `${sats(running)} sats of the ${sats(locked)} locked`
    : `${sats(running)} sats scheduled`);
}

function liabilityCard(d) {
  const { amounts, total, wallet } = d;
  const coverPct = total > 0 ? Math.min(100, (wallet.total / total) * 100) : 100;
  const covered = wallet.known && wallet.total >= total;
  const share = (v) => (total > 0 ? (v / total) * 100 : 0);

  const bar = el('div', { class: 'bar' },
    BUCKETS.map((b) => {
      const value = amounts[b.id];
      if (!value) return null;
      const pct = share(value);
      const seg = el('div', {
        class: `bar-seg ${b.cls}`,
        title: `${b.label}: ${sats(value)} sats (${pct.toFixed(1)}%)`,
      },
        // Only where it fits: a clipped label is worse than none.
        pct >= 11 ? el('span', { class: 'bar-seg-label', text: b.label }) : null);
      seg.style.setProperty('width', `${pct}%`);
      return seg;
    }),
  );

  if (total > 0 && wallet.known && !covered) {
    const shade = el('div', { class: 'bar-uncovered' });
    const mark = el('div', {
      class: 'bar-mark',
      title: `wallet balance covers ${sats(wallet.total)} of ${sats(total)} sats`,
    });
    shade.style.setProperty('--at', `${coverPct}%`);
    mark.style.setProperty('--at', `${coverPct}%`);
    bar.append(shade, mark);
  }

  const body = el('div', { class: 'liab' },
    el('div', { class: 'liab-top' },
      el('div', { class: 'liab-total' },
        el('p', { class: 'eyebrow', text: 'Locked in batches' }),
        btc(d.unswept, { large: true }),
        el('p', { class: 'subline', text: 'unswept batch outputs' }),
      ),
      el('div', { class: 'liab-side' },
        el('p', { class: 'eyebrow', text: 'Total liability' }),
        btc(total),
      ),
      el('div', { class: 'liab-cover' },
        el('p', { class: 'eyebrow', text: 'Covered by wallet' }),
        wallet.known
          ? el('div', {
            class: `liab-cover-pct ${covered ? 'ok' : 'short'}`,
            text: `${coverPct.toFixed(1)}%`,
          })
          : el('div', { class: 'liab-cover-pct', text: '—', title: 'wallet balance unavailable' }),
        el('p', {
          class: 'subline',
          text: wallet.known ? `wallet ${sats(wallet.total)} sats` : d.walletError ?? 'unavailable',
        }),
      ),
    ),

    // The one thing on this page that asks for action.
    amounts.overdue > 0 ? el('div', { class: 'liab-alert' },
      el('span', {}, `${sats(amounts.overdue)} sats past expiry, unswept`),
      el('a', { href: '#/sweeps' }, 'Sweeps →'),
    ) : null,

    total > 0 ? bar : el('p', { class: 'state', text: 'No outstanding liability.' }),

    total > 0 && wallet.known && !covered
      ? el('p', { class: 'bar-caption', text: 'Marker: wallet reach, most urgent first. Shaded is unbacked.' })
      : null,

    el('div', { class: 'legend' },
      BUCKETS.map((b) => {
        const value = amounts[b.id];
        return el('div', { class: `legend-item${value ? '' : ' legend-empty'}` },
          el('span', { class: 'legend-swatch', style: { background: b.swatch } }),
          el('span', { class: 'legend-name', text: b.label }),
          btc(value),
          el('span', { class: 'legend-pct', text: value ? `${share(value).toFixed(0)}%` : '' }),
        );
      }),
    ),
  );

  const note = !wallet.known
    ? 'wallet balance unavailable'
    : covered
      ? `wallet holds ${sats(wallet.total - total)} sats above liability`
      : `short by ${sats(total - wallet.total)} sats`;

  return card('Liability across time', body, note);
}

function tiles(d) {
  const { due72h, wallet, status, feeRate } = d;
  const walletTile = wallet.known
    ? { value: btc(wallet.mainAvailable + wallet.connAvailable), note: `${sats(wallet.mainLocked + wallet.connLocked)} sats locked` }
    : { value: el('span', { class: 'badge warn', text: 'unavailable' }), note: 'locked or unreachable' };

  const items = [
    {
      label: 'Reclaimable within 72h',
      value: btc(due72h),
      note: 'recoverable + past expiry + the three day buckets',
    },
    {
      label: 'Wallet available',
      value: walletTile.value,
      note: walletTile.note,
    },
    {
      label: 'Wallet state',
      value: walletStatus(status),
      note: 'initialized · unlocked · synced',
    },
    {
      label: 'Fee rate',
      value: feeRate
        ? el('span', { text: `${num(feeRate.satPerVbyte).toFixed(2)} sat/vB` })
        : el('span', { class: 'mono', text: '—' }),
      note: feeRate ? `${sats(feeRate.satPerKvbyte)} sat/kvB` : 'unavailable',
    },
  ];

  return el('div', { class: 'tiles' }, items.map((t) =>
    el('div', { class: 'tile' },
      el('div', { class: 'tile-label', text: t.label }),
      el('div', { class: 'tile-value' }, t.value),
      el('div', { class: 'tile-note', text: t.note }),
    )));
}

function walletStatus(s) {
  if (!s) return el('span', { class: 'badge warn', text: 'unknown' });
  const flags = [
    ['init', s?.initialized],
    ['unlocked', s?.unlocked],
    ['synced', s?.synced],
  ];
  const bad = flags.filter(([, ok]) => !ok);
  return el('span', {
    class: bad.length ? 'badge fail' : 'badge ok',
    text: bad.length ? `not ${bad.map(([n]) => n).join(', ')}` : 'ready',
  });
}

function caveats() {
  return card(null, el('details', { class: 'blob card-body' },
    el('summary', { text: 'How these numbers are built' }),
    el('p', { class: 'hint', text:
      'Buckets count unspent VTXOs. Expiring buckets are swept = false and exclude unrolled; recoverable is swept = true and does not.' }),
    el('p', { class: 'hint', text:
      'Notes count as liability; the admin API does not expose them separately.' }),
    el('p', { class: 'hint', text: 'Coverage includes locked wallet UTXOs.' }),
  ));
}
