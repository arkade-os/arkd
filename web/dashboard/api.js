/*
  The only place that talks to arkd.

  Two guarantees this module exists to enforce:

  1. GET only. There is no code path here that can issue another method, so no
     panel can move funds, change settings, or unlock a wallet even by mistake.
  2. The macaroon lives in this closure and nowhere else. It is never written to
     localStorage, sessionStorage, cookies, or the URL, and it is dropped on
     lock, on idle timeout, and on reload.

  A server started with --no-macaroons (regtest) is supported: the session then
  carries no macaroon and requests go out unauthenticated.
*/

const IDLE_LIMIT_MS = 15 * 60 * 1000;

// Without this a slow endpoint leaves the tab spinning forever with no way to
// tell a hang from a wide query. AbortSignal.timeout cancels the fetch itself,
// so the socket goes with it.
const REQUEST_TIMEOUT_MS = 30 * 1000;

// null = disconnected. Otherwise { macaroon } where macaroon is null on a server
// started with --no-macaroons, which is how regtest runs.
let session = null;
let lastActivity = 0;
let idleTimer = null;
const lockListeners = new Set();

/* ------------------------------------------------------------------ config */

export function config() {
  const c = (typeof window !== 'undefined' && window.ARKD) || {};
  return {
    adminUrl: trimSlash(c.adminUrl),
    indexerUrl: trimSlash(c.indexerUrl),
    explorerUrl: trimSlash(c.explorerUrl),
  };
}

// Mainnet by default; signet and regtest set ARKD_EXPLORER_URL to their own.
const DEFAULT_EXPLORER = 'https://arkade.space';

export function explorerBase() {
  const { explorerUrl } = config();
  return /^https?:\/\//.test(explorerUrl) ? explorerUrl : DEFAULT_EXPLORER;
}

/** Why the app cannot start, or null when the config is usable. */
export function configError() {
  const { adminUrl } = config();
  if (!adminUrl) {
    return 'ARKD_ADMIN_URL is not set. Set it on the container and restart — the console has nothing to connect to.';
  }
  if (!/^https?:\/\//.test(adminUrl)) {
    return `ARKD_ADMIN_URL must start with http:// or https://. Got "${adminUrl}".`;
  }
  return null;
}

export function hasIndexer() {
  return Boolean(config().indexerUrl);
}

function trimSlash(v) {
  return String(v ?? '').trim().replace(/\/+$/, '');
}

/* ------------------------------------------------------------ lock / unlock */

export function isUnlocked() {
  return session !== null;
}

/** True when connected to a server that has macaroon auth switched off. */
export function isOpenServer() {
  return session !== null && session.macaroon === null;
}

// The endpoint used to decide whether a credential is required and whether a
// given one works. It must be a *restricted* method: /v1/admin/wallet/status is
// whitelisted and answers without a macaroon even on an authenticated server,
// so probing that would report every server as open. GetSettings needs
// manager:read, which is exactly what readonly.macaroon grants.
const AUTH_PROBE_PATH = '/v1/admin/settings';

/**
 * Probes whether arkd accepts unauthenticated admin reads, i.e. it was started
 * with --no-macaroons. Returns true and connects if so; false means a macaroon
 * is required. Never throws for the ordinary "auth required" answer.
 */
export async function probeOpen() {
  session = { macaroon: null };
  try {
    await adminGet(AUTH_PROBE_PATH);
    touch();
    return true;
  } catch (err) {
    session = null;
    if (err instanceof ApiError && (err.status === 401 || err.status === 403)) return false;
    throw err;
  }
}

/** Accepts the macaroon after a probe request proves arkd will honour it. */
export async function unlock(value) {
  const hex = String(value ?? '').trim().replace(/\s+/g, '');
  if (!hex) throw new ApiError('Enter a macaroon to connect.', 0);
  if (!/^[0-9a-fA-F]+$/.test(hex)) {
    throw new ApiError('That does not look like a hex macaroon. Use the output of `xxd -p -c 1000 readonly.macaroon`.', 0);
  }

  session = { macaroon: hex };
  try {
    await adminGet(AUTH_PROBE_PATH);
  } catch (err) {
    session = null;
    throw err;
  }
  touch();
  return true;
}

export function lock(reason = 'manual') {
  if (session === null) return;
  session = null;
  stopIdleTimer();
  for (const fn of lockListeners) fn(reason);
}

export function onLock(fn) {
  lockListeners.add(fn);
  return () => lockListeners.delete(fn);
}

/* -------------------------------------------------------------- idle timer */

function touch() {
  lastActivity = Date.now();
  // Nothing to protect when there is no macaroon, so no idle lock either.
  if (!idleTimer && session !== null && session.macaroon !== null) startIdleTimer();
}

export function idleRemainingMs() {
  if (session === null || session.macaroon === null) return 0;
  return Math.max(0, IDLE_LIMIT_MS - (Date.now() - lastActivity));
}

function startIdleTimer() {
  stopIdleTimer();
  idleTimer = setInterval(() => {
    if (session === null || session.macaroon === null) return stopIdleTimer();
    if (idleRemainingMs() <= 0) lock('idle');
  }, 5000);
}

function stopIdleTimer() {
  if (idleTimer) clearInterval(idleTimer);
  idleTimer = null;
}

/* ------------------------------------------------------------------ errors */

export class ApiError extends Error {
  constructor(message, status = 0, detail = '') {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.detail = detail;
  }
}

/* ---------------------------------------------------------------- requests */

/** GET against the admin gateway, carrying the macaroon when there is one. */
export function adminGet(path, params) {
  if (session === null) throw new ApiError('Disconnected. Reconnect to continue.', 401);
  const headers = session.macaroon === null ? {} : { 'X-Macaroon': session.macaroon };
  return request(config().adminUrl, path, params, headers);
}

/** Unauthenticated GET against the public indexer gateway. */
export function indexerGet(path, params) {
  const { indexerUrl } = config();
  if (!indexerUrl) throw new ApiError('No indexer URL configured.', 0);
  return request(indexerUrl, path, params, {});
}

async function request(base, path, params, headers) {
  const url = new URL(base + path);
  for (const [k, v] of Object.entries(params ?? {})) {
    if (v === undefined || v === null || v === '') continue;
    if (Array.isArray(v)) for (const item of v) url.searchParams.append(k, String(item));
    else url.searchParams.set(k, String(v));
  }

  let res;
  try {
    res = await fetch(url.toString(), {
      method: 'GET',
      headers,
      credentials: 'omit',
      mode: 'cors',
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  } catch (cause) {
    if (cause?.name === 'TimeoutError') {
      throw new ApiError(
        `arkd did not answer within ${REQUEST_TIMEOUT_MS / 1000}s. Narrow the window or lower the limit, then try again.`,
        0, `GET ${path}`,
      );
    }
    throw new ApiError(
      `Cannot reach ${base}. Check the URL, that arkd is up, and that its TLS certificate is trusted by this browser.`,
      0, String(cause?.message ?? cause),
    );
  }

  const body = await res.text();

  if (!res.ok) {
    const detail = extractError(body);
    if (res.status === 401 || res.status === 403) {
      throw new ApiError('arkd rejected that macaroon. It may be the wrong file, revoked, or for a different server.', res.status, detail);
    }
    if (res.status === 404) {
      throw new ApiError('Not found.', 404, detail);
    }
    throw new ApiError(detail || `arkd returned HTTP ${res.status}.`, res.status, detail);
  }

  touch();

  if (!body) return {};
  try {
    return JSON.parse(body);
  } catch {
    throw new ApiError('arkd returned a response that is not JSON.', res.status, body.slice(0, 200));
  }
}

/** grpc-gateway wraps failures as {code, message, details}. */
function extractError(body) {
  if (!body) return '';
  try {
    const parsed = JSON.parse(body);
    return String(parsed.message ?? parsed.error ?? '').trim();
  } catch {
    return body.slice(0, 200).trim();
  }
}
