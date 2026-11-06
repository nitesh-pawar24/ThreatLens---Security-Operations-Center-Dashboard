/**
 * ThreatLens – API Client Service
 * =================================
 * Communicates with the FastAPI backend engine (/api).
 * Automatically handles network failures and surfaces clear error messages.
 */

/**
 * Base URL for the ThreatLens backend API.
 * In production (e.g. Vercel), this is configured via the VITE_API_BASE_URL environment variable.
 * In local development, if VITE_API_BASE_URL is not set, it defaults to an empty string,
 * which routes through the local Vite development proxy to http://127.0.0.1:8000.
 */
export const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || '').trim().replace(/\/+$/, '');

/**
 * Resolve full API request URL, safely handling any trailing `/api` in VITE_API_BASE_URL.
 */
function resolveUrl(endpoint) {
  if (!API_BASE_URL) {
    return endpoint;
  }
  if (API_BASE_URL.endsWith('/api') && endpoint.startsWith('/api')) {
    return `${API_BASE_URL}${endpoint.slice(4)}`;
  }
  return `${API_BASE_URL}${endpoint}`;
}

/**
 * Default maximum CSV upload size (10 MB). The backend advertises its real limit via
 * /api/health (`limits.max_upload_size_mb`); the UI prefers that value when available.
 */
export const MAX_UPLOAD_SIZE_BYTES = 10 * 1024 * 1024;

// ── Visitor sessions ──────────────────────────────────────────────────────────
// When the backend runs with MULTI_TENANT_SESSIONS=true, every data request must carry an
// X-Session-ID header naming a private, server-issued session. The token is stored in
// sessionStorage (per browser tab, cleared when the tab closes) with an in-memory fallback
// for browsers where storage is unavailable. No admin credential is ever stored or sent.
const SESSION_HEADER = 'X-Session-ID';
const SESSION_STORAGE_KEY = 'threatlens.sessionId';
const SESSION_TOKEN_PATTERN = /^tl_sess_[0-9a-f]{64}$/;

let memorySessionId = null; // fallback when sessionStorage is unavailable
let sessionMode = null; // null = unknown until /api/health has been read
let sessionPromise = null; // single in-flight session creation (de-duplicates concurrent callers)
let capabilityPromise = null; // single in-flight capability discovery
let sessionWasReset = false; // set when an expired/invalid session had to be replaced

function readStoredSession() {
  try {
    const value = window.sessionStorage.getItem(SESSION_STORAGE_KEY);
    if (value && SESSION_TOKEN_PATTERN.test(value)) return value;
    if (value) window.sessionStorage.removeItem(SESSION_STORAGE_KEY);
  } catch {
    // sessionStorage unavailable (private mode, blocked): use the in-memory copy
  }
  return memorySessionId && SESSION_TOKEN_PATTERN.test(memorySessionId) ? memorySessionId : null;
}

function storeSession(id) {
  memorySessionId = id;
  try {
    window.sessionStorage.setItem(SESSION_STORAGE_KEY, id);
  } catch {
    // in-memory copy still works for this page lifetime
  }
}

function clearStoredSession() {
  memorySessionId = null;
  try {
    window.sessionStorage.removeItem(SESSION_STORAGE_KEY);
  } catch {
    // nothing to clear
  }
}

/** Drop the stored token only if it is still the one that was rejected (avoids racing a newer one). */
function invalidateSession(rejectedToken) {
  if (readStoredSession() === rejectedToken) clearStoredSession();
}

/** True if a rejected/expired session was transparently replaced since the last call. */
export function consumeSessionReset() {
  const was = sessionWasReset;
  sessionWasReset = false;
  return was;
}

/** Whether the backend is in per-visitor session mode (null until the first health check). */
export function isSessionMode() {
  return sessionMode;
}

/**
 * Return the current session token, creating one if needed. Concurrent callers share one
 * creation request, so React StrictMode / parallel fetches never leak extra sessions.
 */
export async function ensureSession() {
  const existing = readStoredSession();
  if (existing) return existing;
  if (!sessionPromise) {
    sessionPromise = apiRequest('/api/session', { method: 'POST' }, { withSession: false })
      .then((data) => {
        storeSession(data.session_id);
        return data.session_id;
      })
      .finally(() => {
        sessionPromise = null;
      });
  }
  return sessionPromise;
}

/** Learn whether the backend needs sessions before the first data request is sent. */
function discoverCapabilities() {
  if (!capabilityPromise) {
    capabilityPromise = checkHealth().finally(() => {
      capabilityPromise = null;
    });
  }
  return capabilityPromise;
}

/**
 * Helper to perform fetch requests with unified error handling.
 * In session mode it attaches X-Session-ID and, if the backend reports the session as
 * missing/expired (HTTP 401), transparently creates a fresh session and retries once.
 */
async function apiRequest(endpoint, options = {}, { withSession = true } = {}) {
  const url = resolveUrl(endpoint);
  try {
    for (let attempt = 0; ; attempt += 1) {
      let token = null;
      if (withSession) {
        if (sessionMode === null) await discoverCapabilities();
        if (sessionMode) token = await ensureSession();
      }

      const headers = { ...(options.headers || {}) };
      if (token) headers[SESSION_HEADER] = token;
      const res = await fetch(url, { ...options, headers });

      if (res.status === 401 && token && attempt === 0) {
        invalidateSession(token);
        sessionWasReset = true;
        continue;
      }

      if (!res.ok) {
        let errorMsg = `Server error (${res.status})`;
        let hasDetail = false;
        try {
          const errorData = await res.json();
          if (errorData.detail) {
            hasDetail = true;
            errorMsg = Array.isArray(errorData.detail)
              ? errorData.detail.map((e) => e.msg).join(', ')
              : typeof errorData.detail === 'string'
                ? errorData.detail
                : errorData.detail.message || errorMsg;
          }
        } catch {
          if (res.statusText) errorMsg = res.statusText;
        }
        const error = new Error(errorMsg);
        error.status = res.status;
        error.fromApp = hasDetail; // a ThreatLens JSON error, not a proxy/gateway page
        throw error;
      }

      return await res.json();
    }
  } catch (err) {
    if (err.name === 'TypeError' || (err.message && err.message.toLowerCase().includes('fetch'))) {
      const targetHint = API_BASE_URL || 'http://localhost:8000';
      const connErr = new Error(
        `Cannot connect to ThreatLens API server (${targetHint}). Is the backend active and reachable?`
      );
      connErr.isNetworkError = true;
      throw connErr;
    }
    throw err;
  }
}

/** Health check: verify API server status and detection engine state */
export async function checkHealth() {
  const health = await apiRequest('/api/health', {}, { withSession: false });
  sessionMode = Boolean(health?.multi_tenant);
  return health;
}

/** Retrieve summary metrics, activity chart, severity breakdown, and suspicious IPs */
export async function getSummary() {
  return await apiRequest('/api/summary');
}

/**
 * Retrieve alerts list with optional filters applied server-side.
 * @param {Object} opts
 * @param {string} [opts.severity] - 'All' | 'Critical' | 'High' | 'Medium' | 'Low'
 * @param {string} [opts.status]   - 'All' | 'Open' | 'Investigating' | 'Resolved' | 'False Positive'
 * @param {string} [opts.event_type] - 'All' | e.g. 'LOGIN_FAILURE'
 * @param {string} [opts.source_ip]  - partial IP string
 * @param {string} [opts.search]     - free text search
 */
export async function getAlerts({ severity, status, event_type, source_ip, search } = {}) {
  const params = new URLSearchParams();
  if (severity && severity !== 'All') params.append('severity', severity);
  if (status && status !== 'All') params.append('status', status);
  if (event_type && event_type !== 'All') params.append('event_type', event_type);
  if (source_ip && source_ip.trim()) params.append('source_ip', source_ip.trim());
  if (search && search.trim()) params.append('search', search.trim());

  const query = params.toString() ? `?${params.toString()}` : '';
  return await apiRequest(`/api/alerts${query}`);
}

/** Retrieve parsed log entries with optional log level or text search filters */
export async function getLogs({ level, search, limit = 200 } = {}) {
  const params = new URLSearchParams();
  if (level && level !== 'All') params.append('level', level);
  if (search && search.trim()) params.append('search', search.trim());
  if (limit) params.append('limit', limit);

  const query = params.toString() ? `?${params.toString()}` : '';
  return await apiRequest(`/api/logs${query}`);
}

/**
 * Upload and analyze a CSV log file with the Python detection engine.
 * Client-side size/type validation must occur before calling this.
 */
export async function uploadAndAnalyzeCsv(file) {
  const formData = new FormData();
  formData.append('file', file);
  return await apiRequest('/api/analyze', { method: 'POST', body: formData });
}

/**
 * Upload and import an exported Windows Security Event Viewer CSV file.
 * Returns normalized events, detected alerts, and an import report.
 */
export async function uploadWindowsLog(file) {
  const formData = new FormData();
  formData.append('file', file);
  return await apiRequest('/api/analyze/windows', { method: 'POST', body: formData });
}

/** Retrieve supported Windows Event IDs and schema mappings */
export async function getWindowsSupportedEvents() {
  return await apiRequest('/api/windows/supported-events');
}

/** Reset the backend engine (resets to clean empty state by default) */
export async function resetToSample({ sample = false } = {}) {
  const query = sample ? '?sample=true' : '';
  return await apiRequest(`/api/reset${query}`, { method: 'POST' });
}

/** Explicitly load the synthetic sample dataset into the backend */
export async function loadStandardSample() {
  return await apiRequest('/api/sample', { method: 'POST' });
}

/** Retrieve current detection configuration and defaults */
export async function getDetectionConfig() {
  return await apiRequest('/api/detection/config');
}

/**
 * Update detection configuration thresholds.
 * @param {Object} updates - Partial config object with fields to update.
 */
export async function updateDetectionConfig(updates) {
  return await apiRequest('/api/detection/config', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(updates),
  });
}
