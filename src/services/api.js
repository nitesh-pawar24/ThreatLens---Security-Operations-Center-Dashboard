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

/** Maximum CSV upload size – mirrors backend MAX_UPLOAD_SIZE_BYTES (10 MB) */
export const MAX_UPLOAD_SIZE_BYTES = 10 * 1024 * 1024;

/**
 * Helper to perform fetch requests with unified error handling.
 */
async function apiRequest(endpoint, options = {}) {
  const url = resolveUrl(endpoint);
  try {
    const res = await fetch(url, { ...options });

    if (!res.ok) {
      let errorMsg = `Server error (${res.status})`;
      try {
        const errorData = await res.json();
        if (errorData.detail) {
          errorMsg = Array.isArray(errorData.detail)
            ? errorData.detail.map((e) => e.msg).join(', ')
            : errorData.detail;
        }
      } catch {
        if (res.statusText) errorMsg = res.statusText;
      }
      const error = new Error(errorMsg);
      error.status = res.status;
      throw error;
    }

    return await res.json();
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
  return await apiRequest('/api/health');
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
