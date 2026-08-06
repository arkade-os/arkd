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
import { card, panelHead, skeleton, errorState } from './table.js';

const DAY = 86400;

/* Left to right: overdue sits before "now" where it should not exist. */
const BUCKETS = [
  { id: 'overdue',     label: 'Overdue',      axis: 'past',   cls: 'overdue',     swatch: 'var(--oxide)' },
  { id: 'd1',          label: 'Under 1 day',  axis: 'now',    cls: 'd1',          swatch: 'var(--amber)' },
  { id: 'd2',          label: '1 – 2 days',   axis: null,     cls: 'd2',          swatch: '#b9793c' },
  { id: 'd3',          label: '2 – 3 days',   axis: null,     cls: 'd3',          swatch: '#8f6134' },
  { id: 'later',       label: 'Over 3 days',  axis: '3d+',    cls: 'later',       swatch: 'var(--gold-dim)' },
  { id: 'recoverable', label: 'Recoverable',  axis: 'swept',  cls: 'recoverable', swatch: 'var(--teal)' },
];

export function solvencyPanel() {
  const body = el('div', {});
  const node = el('div', {},
    panelHead('Overview', 'What the server owes, when it comes due, and what is available to cover it.'),
    body,
  );

  async function reload() {
    clear(body).append(card(null, skeleton()));
    try {
      clear(body).append(...render(await load()));
    } catch (err) {
      clear(body).append(card(null, errorState(err)));
    }
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
  const optional = (p) => p.then((v) => ({ ok: true, value: v }), (err) => ({ ok: false, err }));

  const [overdue, d1, d2, d3, later, recoverable, balanceRes, statusRes, feeRateRes] =
    await Promise.all([
      expiring(1, now),
      expiring(now, now + DAY),
      expiring(now + DAY, now + 2 * DAY),
      expiring(now + 2 * DAY, now + 3 * DAY),
      expiring(now + 3 * DAY, 0),
      adminGet('/v1/admin/liquidity/recoverable').then((r) => num(r.amount)),
      optional(adminGet('/v1/admin/wallet/balance')),
      optional(adminGet('/v1/admin/wallet/status')),
      optional(adminGet('/v1/admin/feeRate')),
    ]);

  const balance = balanceRes.ok ? balanceRes.value : null;
  const status = statusRes.ok ? statusRes.value : null;
  const feeRate = feeRateRes.ok ? feeRateRes.value : null;
  const walletError = balanceRes.ok ? null : (balanceRes.err?.message ?? 'unavailable');

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

function render(d) {
  return [
    liabilityCard(d),
    tiles(d),
    caveats(),
  ];
}

function liabilityCard(d) {
  const { amounts, total, wallet } = d;
  const coverPct = total > 0 ? Math.min(100, (wallet.total / total) * 100) : 100;
  const covered = wallet.known && wallet.total >= total;

  const bar = el('div', { class: 'bar' },
    BUCKETS.map((b) => {
      const value = amounts[b.id];
      if (!value) return null;
      const seg = el('div', {
        class: `bar-seg ${b.cls}`,
        title: `${b.label}: ${sats(value)} sats`,
      });
      seg.style.setProperty('width', `${(value / total) * 100}%`);
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
        el('p', { class: 'eyebrow', text: 'Total liability' }),
        btc(total, { large: true }),
      ),
      el('div', { class: 'liab-cover' },
        el('p', { class: 'eyebrow', text: 'Covered by wallet' }),
        wallet.known
          ? el('div', {
            class: `liab-cover-pct ${covered ? 'ok' : 'short'}`,
            text: `${coverPct.toFixed(1)}%`,
          })
          : el('div', { class: 'liab-cover-pct', text: '—', title: 'wallet balance unavailable' }),
      ),
    ),

    total > 0 ? bar : el('p', { class: 'state', text: 'No outstanding liability.' }),

    // No axis scale here on purpose: segment widths are amounts, so evenly
    // spaced time labels would point at the wrong places. The legend below is
    // in the same order and carries the exact figures.
    total > 0 && wallet.known && !covered
      ? el('p', { class: 'bar-caption', text: 'Marker shows how far the wallet balance reaches, paying most urgent first. Everything shaded to its right is unbacked.' })
      : null,
    d.walletError
      ? el('p', { class: 'bar-caption', text: `Coverage unavailable: ${d.walletError}` })
      : null,

    el('div', { class: 'legend' },
      BUCKETS.map((b) => el('div', { class: 'legend-item' },
        el('span', { class: 'legend-swatch', style: { background: b.swatch } }),
        el('span', { class: 'legend-name', text: b.label }),
        btc(amounts[b.id]),
      )),
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
  const { amounts, unswept, due72h, wallet, status, feeRate } = d;
  const walletTile = wallet.known
    ? { value: btc(wallet.mainAvailable + wallet.connAvailable), note: `${sats(wallet.mainLocked + wallet.connLocked)} sats locked` }
    : { value: el('span', { class: 'badge warn', text: 'unavailable' }), note: 'wallet is locked or unreachable' };

  const items = [
    {
      label: 'Due within 72h',
      value: btc(due72h),
      note: 'recoverable + overdue + the three day buckets',
    },
    {
      label: 'Locked in batches',
      value: btc(unswept),
      note: 'unswept batch outputs, not yet claimable by you',
    },
    {
      label: 'Overdue, unswept',
      value: btc(amounts.overdue),
      note: amounts.overdue > 0 ? 'expired but never swept — invisible to liquidity-report' : 'nothing past due',
      alert: amounts.overdue > 0,
    },
    {
      label: 'Wallet available',
      value: walletTile.value,
      note: walletTile.note,
    },
    {
      label: 'Wallet',
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
    el('div', { class: `tile${t.alert ? ' alert' : ''}` },
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
  return card('How these numbers are built', el('div', { class: 'card-body' },
    el('p', { class: 'panel-sub', text:
      'Every bucket counts unspent VTXOs only. The expiring buckets are swept = false and exclude unrolled VTXOs; recoverable is swept = true and does not exclude them, so a unilaterally exited VTXO that was later swept still counts here.' }),
    el('p', { class: 'hint', text:
      'Notes are counted as liability. They are operator-minted, so the true user-owed figure is lower by the outstanding note value, which the admin API does not expose separately.' }),
    el('p', { class: 'hint', text:
      'Coverage compares total liability against the wallet balance including locked UTXOs. Locked funds are still yours, but they are reserved and not immediately spendable.' }),
  ));
}
