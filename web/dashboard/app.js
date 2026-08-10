/*
  Shell: connect gate, hash router, nav, refresh, lock.

  Routes are hash-based so every drill-down is a real link — you can paste a
  batch URL to someone and the back button behaves.
*/

import { el, clear, short } from './fmt.js';
import * as api from './api.js';
import * as panels from './panels.js';
import { combine } from './table.js';
import { solvencyPanel } from './solvency.js';
import { batchPanel } from './batch.js';
import { offchainTxPanel } from './offchainTx.js';
import { commitmentPanel, vtxoPanel } from './indexer.js';

/* ------------------------------------------------------------------ routes */

const ROUTES = [
  { path: '', group: null, nav: 'Overview', title: 'Overview', make: solvencyPanel },

  { path: 'batches', group: 'Batches', nav: 'Batches', title: 'Batches', make: panels.batches },
  { path: 'sweeps', group: 'Batches', nav: 'Scheduled sweeps', title: 'Scheduled sweeps', make: panels.scheduledSweeps },

  { path: 'offchain', group: 'Flow', nav: 'Offchain txs', title: 'Offchain transactions', make: panels.offchainTxs },
  { path: 'intents', group: 'Flow', nav: 'Intent queue', title: 'Intent queue', make: panels.intentQueue },

  { path: 'convictions', group: 'Policy', nav: 'Convictions', title: 'Convictions', make: panels.convictions },
  {
    path: 'config',
    group: 'Policy',
    nav: 'Config',
    title: 'Config',
    make: () => combine(
      'Config',
      'Live server configuration. Change it with the arkd CLI.',
      [bare(panels.settings), bare(panels.scheduledSession)],
    ),
  },
  {
    path: 'fees',
    group: 'Policy',
    nav: 'Fees',
    title: 'Fees',
    make: () => combine(
      'Fees',
      'What the server charges, and what it collected.',
      [bare(panels.fees), bare(panels.collectedFees)],
    ),
  },

  {
    path: 'wallet',
    group: 'Wallet',
    nav: 'Wallet',
    title: 'Wallet',
    make: () => combine(
      'Wallet',
      'Wallet balance and UTXO set. Read-only.',
      [bare(panels.wallet), bare(panels.walletUtxos)],
    ),
  },

  { path: 'vtxo', group: 'Indexer', nav: 'VTXO lookup', title: 'VTXO lookup', indexer: true, make: panels.vtxoLookup },

  // Detail routes: reachable by link, not listed in the nav.
  { path: 'batch/:id', title: 'Batch', make: (p) => batchPanel(p.id), crumb: (p) => ['Batches', '#/batches', short(p.id, 10, 6)] },
  { path: 'offchain/:txid', title: 'Offchain tx', make: (p) => offchainTxPanel(p.txid), crumb: (p) => ['Offchain txs', '#/offchain', short(p.txid, 10, 6)] },
  { path: 'commitment/:txid', title: 'Commitment', indexer: true, make: (p) => commitmentPanel(p.txid), crumb: (p) => ['Batches', '#/batches', short(p.txid, 10, 6)] },
  { path: 'vtxo/:txid/:vout', title: 'VTXO', indexer: true, make: (p) => vtxoPanel(p.txid, p.vout), crumb: (p) => ['VTXO lookup', '#/vtxo', `${short(p.txid, 8, 6)}:${p.vout}`] },
];

/** A panel mounted inside combine(): it drops its own heading. */
function bare(factory) {
  return factory({ bare: true });
}

/* -------------------------------------------------------------------- boot */

const dom = {};

function grab() {
  for (const id of [
    'gate', 'gate-form', 'gate-macaroon', 'gate-error', 'gate-submit',
    'gate-admin-url', 'gate-indexer-url', 'misconfig', 'misconfig-msg',
    'app', 'rail-nav', 'view', 'crumbs', 'lock-btn', 'refresh-btn',
    'conn-dot', 'conn-label', 'idle-label', 'fetched-at',
  ]) {
    dom[id] = document.getElementById(id);
  }
}

function boot() {
  grab();

  const problem = api.configError();
  if (problem) {
    dom['misconfig-msg'].textContent = problem;
    dom.misconfig.hidden = false;
    return;
  }

  const cfg = api.config();
  dom['gate-admin-url'].textContent = cfg.adminUrl;
  dom['gate-indexer-url'].textContent = cfg.indexerUrl || 'not configured — indexer panels hidden';

  dom['gate-form'].addEventListener('submit', onConnect);
  dom['lock-btn'].addEventListener('click', () => api.lock('manual'));
  dom['refresh-btn'].addEventListener('click', () => void render());
  window.addEventListener('hashchange', () => void render());

  api.onLock(showGate);

  // A server started with --no-macaroons (regtest) needs no credential at all,
  // so try that first and skip the gate when it works.
  void openOrGate();
}

async function openOrGate() {
  dom['gate-submit'].disabled = true;
  dom['gate-submit'].textContent = 'Checking\u2026';
  try {
    if (await api.probeOpen()) return enterApp();
  } catch {
    // Unreachable or TLS refused: fall through to the gate, where the retry
    // surfaces the real error.
  } finally {
    dom['gate-submit'].disabled = false;
    dom['gate-submit'].textContent = 'Connect';
  }
  showGate();
}

/* -------------------------------------------------------------------- gate */

function showGate() {
  dom.app.hidden = true;
  dom.gate.hidden = false;
  dom.misconfig.hidden = true;
  dom['gate-macaroon'].value = '';
  dom['gate-error'].hidden = true;
  clear(dom.view);
  stopClock();
  dom['gate-macaroon'].focus();
}

async function onConnect(event) {
  event.preventDefault();
  const input = dom['gate-macaroon'];
  const btn = dom['gate-submit'];

  btn.disabled = true;
  btn.textContent = 'Connecting…';
  dom['gate-error'].hidden = true;

  try {
    await api.unlock(input.value);
    input.value = '';
    await enterApp();
  } catch (err) {
    dom['gate-error'].textContent = err?.message ?? String(err);
    dom['gate-error'].hidden = false;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Connect';
  }
}

/* --------------------------------------------------------------------- nav */

async function enterApp() {
  dom.gate.hidden = true;
  dom.misconfig.hidden = true;
  dom.app.hidden = false;
  buildNav();
  startClock();

  // Assigning location.hash fires hashchange, which renders. Only render
  // directly when the hash is already what we want and no event will fire.
  const target = location.hash && location.hash !== '#' ? location.hash : '#/';
  if (location.hash === target) await render();
  else location.hash = target;
}

function buildNav() {
  const nav = clear(dom['rail-nav']);
  let lastGroup;

  for (const route of ROUTES) {
    if (!route.nav) continue;
    if (route.indexer && !api.hasIndexer()) continue;

    if (route.group && route.group !== lastGroup) {
      nav.append(el('li', { class: 'rail-group' }, el('span', { class: 'eyebrow', text: route.group })));
      lastGroup = route.group;
    }
    nav.append(el('li', {}, el('a', { href: `#/${route.path}`, 'data-path': route.path }, route.nav)));
  }
}

function markNav(path) {
  for (const a of dom['rail-nav'].querySelectorAll('a')) {
    a.classList.toggle('on', a.dataset.path === path);
  }
}

/* ------------------------------------------------------------------ router */

/** Match "batch/:id" style patterns. Returns params or null. */
function matchRoute(hash) {
  const path = hash.replace(/^#\/?/, '').replace(/\/+$/, '');
  const parts = path ? path.split('/') : [];

  for (const route of ROUTES) {
    const spec = route.path ? route.path.split('/') : [];
    if (spec.length !== parts.length) continue;

    const params = {};
    let ok = true;
    for (let i = 0; i < spec.length; i += 1) {
      if (spec[i].startsWith(':')) params[spec[i].slice(1)] = decodeURIComponent(parts[i]);
      else if (spec[i] !== parts[i]) { ok = false; break; }
    }
    if (ok) return { route, params, path };
  }
  return null;
}

let current = null;

// Renders are serialized. Two overlapping ones would each clear the panel body,
// await their fetches, then append — leaving two copies of everything.
let chain = Promise.resolve();

function render() {
  chain = chain.then(doRender, doRender);
  return chain;
}

async function doRender() {
  if (!api.isUnlocked()) return;

  dom['refresh-btn'].disabled = true;
  try {
    await route();
  } finally {
    dom['refresh-btn'].disabled = false;
  }
}

async function route() {

  const match = matchRoute(location.hash);
  if (!match) {
    clear(dom.view).append(el('div', { class: 'state' },
      el('p', { class: 'state-title', text: 'No such page' }),
      el('p', {}, 'Try ', el('a', { href: '#/' }, 'Overview'), '.'),
    ));
    setCrumbs(['Not found']);
    markNav(null);
    return;
  }

  const { route, params, path } = match;

  if (route.indexer && !api.hasIndexer()) {
    clear(dom.view).append(el('div', { class: 'state' },
      el('p', { class: 'state-title', text: 'Indexer not configured' }),
      el('p', { text: 'Set ARKD_INDEXER_URL on the container to enable tree, forfeit, and VTXO inspection.' }),
    ));
    setCrumbs([route.title]);
    return;
  }

  // Re-entering the same route (or hitting Refresh) reuses the mounted panel so
  // filter selections survive, and just refetches.
  const key = path;
  if (current?.key === key) {
    await current.panel.reload();
    stampFetched();
    return;
  }

  const panel = route.make(params);
  current = { key, panel };

  markNav(route.path);
  setCrumbs(route.crumb ? route.crumb(params) : [route.title]);

  clear(dom.view).append(panel.node);
  await panel.reload();
  stampFetched();
}

function setCrumbs(parts) {
  const node = clear(dom.crumbs);
  if (parts.length === 3) {
    const [label, href, tail] = parts;
    node.append(
      el('a', { href }, label),
      el('span', { class: 'sep', text: '/' }),
      el('strong', { class: 'mono', text: tail }),
    );
    return;
  }
  node.append(el('strong', { text: parts[0] }));
}

function stampFetched() {
  dom['fetched-at'].textContent = `fetched ${new Date().toLocaleTimeString('en-GB')}`;
}

/* --------------------------------------------------------------- idle clock */

let clockTimer = null;

function startClock() {
  stopClock();

  if (api.isOpenServer()) {
    dom['conn-dot'].classList.remove('warn');
    dom['conn-label'].textContent = 'no auth';
    dom['idle-label'].textContent = 'server runs with macaroons disabled';
    dom['lock-btn'].textContent = 'Disconnect';
    return;
  }

  dom['lock-btn'].textContent = 'Lock';
  const tick = () => {
    const ms = api.idleRemainingMs();
    const mins = Math.floor(ms / 60000);
    const secs = Math.floor((ms % 60000) / 1000);
    dom['idle-label'].textContent = `locks in ${mins}:${String(secs).padStart(2, '0')}`;
    const soon = ms < 120000;
    dom['conn-dot'].classList.toggle('warn', soon);
    dom['conn-label'].textContent = soon ? 'locking soon' : 'connected';
  };
  tick();
  clockTimer = setInterval(tick, 1000);
}

function stopClock() {
  if (clockTimer) clearInterval(clockTimer);
  clockTimer = null;
}

boot();
