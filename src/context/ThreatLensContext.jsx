/**
 * ThreatLens – Global Threat Context
 * ===================================
 * Manages application mode (LIVE vs DEMO) with strict data isolation.
 *
 * LIVE MODE:
 *   - Shows ONLY real data uploaded by the user (isSample === false).
 *   - If no real data has been uploaded, displays zero/empty metrics.
 *   - Backend disconnection shows a connection error — NEVER falls back to demo data.
 *   - Switching to Live Mode fetches the current backend state; if it only has
 *     the auto-loaded sample it is treated as "no real data yet".
 *
 * DEMO MODE:
 *   - Displays entirely from the static demoData.js dataset.
 *   - Backend is not queried for display data (health check still runs).
 *   - Demo data never crosses into the live data stores.
 *
 * Data isolation invariants:
 *   - liveAlerts / liveSummary / liveLogs are never populated from demo data.
 *   - Demo data variables are never modified by uploads or resets.
 *   - Switching modes never merges the two datasets.
 *   - Demo reset does not touch liveAlerts / liveSummary / liveLogs.
 *   - Live reset calls /api/reset then re-fetches backend state.
 */

import { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react';
import {
  checkHealth,
  getSummary,
  getAlerts,
  getLogs,
  uploadAndAnalyzeCsv,
  uploadWindowsLog,
  resetToSample,
  consumeSessionReset,
  MAX_UPLOAD_SIZE_BYTES,
} from '../services/api';
import {
  summaryStats as demoSummaryStats,
  activityData as demoActivityData,
  severityData as demoSeverityData,
  recentAlerts as demoRecentAlerts,
  suspiciousIPs as demoSuspiciousIPs,
  logEntries as demoLogEntries,
} from '../data/demoData';

const ThreatLensContext = createContext(null);

export { MAX_UPLOAD_SIZE_BYTES };

// ── Zero-value live state shown when no real data is available ────────────────
const LIVE_EMPTY_SUMMARY_STATS = {
  totalEvents: 0,
  threatsDetected: 0,
  criticalAlerts: 0,
  uniqueIPs: 0,
  highPriorityAlerts: 0,
};

const LIVE_EMPTY_SEVERITY_DATA = [
  { name: 'Critical', value: 0, color: '#ef4444' },
  { name: 'High',     value: 0, color: '#f97316' },
  { name: 'Medium',   value: 0, color: '#eab308' },
  { name: 'Low',      value: 0, color: '#22c55e' },
];

export function ThreatLensProvider({ children }) {
  // ── Application mode: 'live' | 'demo' ──────────────────────────────────────
  const [appMode, setAppModeState] = useState('live');

  // ── Backend connectivity ────────────────────────────────────────────────────
  const [backendStatus, setBackendStatus] = useState('checking'); // 'connected' | 'disconnected' | 'checking'
  const [engineInfo, setEngineInfo] = useState(null);

  // ── Live backend data (isolated from demo) ─────────────────────────────────
  const [liveSummary, setLiveSummary] = useState(null);   // null = not fetched yet
  const [liveAlerts, setLiveAlerts] = useState([]);
  const [liveLogs, setLiveLogs] = useState([]);
  const [hasRealData, setHasRealData] = useState(false);  // true only when isSample === false
  const [isLoading, setIsLoading] = useState(true);
  const [apiError, setApiError] = useState(null);

  // ── Upload state ────────────────────────────────────────────────────────────
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState(null);
  const [uploadResult, setUploadResult] = useState(null);

  // Set when the backend expired the visitor's session and a fresh, empty one replaced it
  const [sessionNotice, setSessionNotice] = useState(null);

  // Monotonically increasing sequence – prevents stale responses overwriting newer results
  const uploadSeqRef = useRef(0);

  // ── Backend capabilities (from /api/health) ─────────────────────────────────
  // uploads_enabled is the backend's own answer to "may visitors upload right now?".
  // Older backends only send read_only, so fall back to its inverse.
  const uploadsEnabled = engineInfo ? (engineInfo.uploads_enabled ?? !engineInfo.read_only) : true;
  const isSessionMode = Boolean(engineInfo?.multi_tenant);
  const advertisedMaxMb = Number(engineInfo?.limits?.max_upload_size_mb);
  const maxUploadBytes = advertisedMaxMb > 0 ? advertisedMaxMb * 1024 * 1024 : MAX_UPLOAD_SIZE_BYTES;

  // ── Fetch real backend data ─────────────────────────────────────────────────
  const loadBackendData = useCallback(async () => {
    setIsLoading(true);
    setApiError(null);
    try {
      const health = await checkHealth();
      setEngineInfo(health);
      setBackendStatus('connected');

      const [summaryRes, alertsRes, logsRes] = await Promise.all([
        getSummary(),
        getAlerts(),
        getLogs(),
      ]);

      setLiveSummary(summaryRes);
      setLiveAlerts(alertsRes.alerts || []);
      setLiveLogs(logsRes.logs || []);

      // hasRealData: true only when the backend holds real data with processed rows
      const hasReal = Boolean(
        summaryRes?.metadata?.isSample === false &&
        (summaryRes?.metadata?.rowsProcessed ?? 0) > 0
      );
      setHasRealData(hasReal);

      // The backend replaced an expired or deleted session: notify the visitor why data is cleared
      if (consumeSessionReset() && !hasReal) {
        setSessionNotice(
          'Your session expired after a period of inactivity, so your uploaded data was cleared. Upload your CSV again to continue.'
        );
      }
    } catch (err) {
      console.warn('ThreatLens backend not reachable:', err.message);
      // A ThreatLens 503 (server at visitor/analysis capacity) means the backend IS reachable.
      setBackendStatus(err.status === 503 && err.fromApp ? 'connected' : 'disconnected');
      setApiError(err.message || 'Unable to connect to Python backend.');
      // LIVE MODE: do NOT fall back to demo data. Keep live stores empty.
    } finally {
      setIsLoading(false);
    }
  }, []);

  // Initial load
  useEffect(() => {
    // oxlint-disable-next-line react/set-state-in-effect
    loadBackendData();
  }, [loadBackendData]);

  // ── Mode switching ──────────────────────────────────────────────────────────
  const setAppMode = useCallback((newMode) => {
    setAppModeState(newMode);
    if (newMode === 'live') {
      // Switching to Live: fetch backend state (never carry demo data in)
      loadBackendData();
    }
    // Switching to Demo: nothing to do — demo data is always in demoData.js
  }, [loadBackendData]);

  // ── Upload CSV (Live Mode only) ─────────────────────────────────────────────
  /**
   * Upload a CSV for analysis. Only valid in Live Mode.
   * Uses request sequencing to prevent stale responses.
   * On failure, restores the previous live dataset (never substitutes demo data).
   */
  const handleUploadCsv = async (file, { format = 'auto' } = {}) => {
    // Client-side validation
    if (!file.name.toLowerCase().endsWith('.csv')) {
      const err = new Error('Invalid file type. Only CSV files (.csv) are accepted.');
      setUploadError(err.message);
      throw err;
    }
    if (file.size === 0) {
      const err = new Error('The selected file is empty. Please choose a non-empty CSV file.');
      setUploadError(err.message);
      throw err;
    }
    if (file.size > maxUploadBytes) {
      const limitMb = maxUploadBytes / (1024 * 1024);
      const fileMb = (file.size / (1024 * 1024)).toFixed(1);
      const err = new Error(
        `File is too large (${fileMb} MB). Maximum allowed size is ${limitMb} MB.`
      );
      setUploadError(err.message);
      throw err;
    }

    // Snapshot previous live state for rollback
    const prevSummary = liveSummary;
    const prevAlerts  = liveAlerts;
    const prevLogs    = liveLogs;
    const prevHasReal = hasRealData;

    uploadSeqRef.current += 1;
    const mySeq = uploadSeqRef.current;

    setUploading(true);
    setUploadError(null);
    setUploadResult(null);

    try {
      const result =
        format === 'windows'
          ? await uploadWindowsLog(file)
          : await uploadAndAnalyzeCsv(file);

      if (mySeq !== uploadSeqRef.current) return result;

      setUploadResult({
        filename:       result.filename,
        format:         result.format || 'standard',
        rowsProcessed:  result.rows_processed,
        alertsDetected: result.alerts_detected,
        importReport:   result.import_report || null,
        timestamp:      new Date().toLocaleTimeString(),
      });

      // A successful upload defines the session's data; any earlier expiry notice is moot
      consumeSessionReset();
      setSessionNotice(null);

      // Update live stores from real upload result
      if (result.summary) setLiveSummary(result.summary);
      if (result.alerts) setLiveAlerts(result.alerts);
      setHasRealData(true); // Any successful upload is real data

      // Switch to Live Mode to display the results
      setAppModeState('live');

      // Refresh logs
      try {
        const logsRes = await getLogs();
        if (mySeq === uploadSeqRef.current) {
          setLiveLogs(logsRes.logs || []);
        }
      } catch {
        // Non-critical – keep previous logs
      }

      setBackendStatus('connected');
      setApiError(null);
      return result;
    } catch (err) {
      if (mySeq === uploadSeqRef.current) {
        const msg = err.message || 'CSV upload and analysis failed.';
        setUploadError(msg);
        // Restore previous live state — NEVER substitute demo data
        setLiveSummary(prevSummary);
        setLiveAlerts(prevAlerts);
        setLiveLogs(prevLogs);
        setHasRealData(prevHasReal);
      }
      throw err;
    } finally {
      if (mySeq === uploadSeqRef.current) {
        setUploading(false);
      }
    }
  };

  // ── Live reset: resets backend to sample, marks as "no real data" ───────────
  /**
   * Reset backend to default sample dataset.
   * Live stores are updated to reflect the backend sample state,
   * and hasRealData is set to false (sample ≠ real uploaded data).
   * Demo data is NOT touched.
   */
  const handleResetSample = async () => {
    setIsLoading(true);
    setUploadResult(null);
    setUploadError(null);
    try {
      await resetToSample();
      await loadBackendData(); // re-fetches; sets hasRealData=false (sample)
    } catch (err) {
      setApiError(err.message || 'Failed to reset dataset.');
    } finally {
      setIsLoading(false);
    }
  };

  // ── Derived display values ──────────────────────────────────────────────────
  // In LIVE MODE: show real data only when hasRealData; otherwise zeros/empty.
  // In DEMO MODE: always show demoData.js values.

  const isLiveMode = appMode === 'live';
  const isDemoMode = appMode === 'demo';

  // isUsingBackend: true only in live mode when backend is connected AND real data exists
  const isUsingBackend = isLiveMode && backendStatus === 'connected' && hasRealData;

  // Live display values: real data or empty state (never demo)
  const liveDisplaySummaryStats  = hasRealData && liveSummary ? liveSummary.summaryStats  : LIVE_EMPTY_SUMMARY_STATS;
  const liveDisplayActivityData  = hasRealData && liveSummary?.activityData?.length > 0  ? liveSummary.activityData  : [];
  const liveDisplaySeverityData  = hasRealData && liveSummary ? liveSummary.severityData  : LIVE_EMPTY_SEVERITY_DATA;
  const liveDisplayAlerts        = hasRealData ? liveAlerts : [];
  const liveDisplaySuspiciousIPs = hasRealData && liveSummary?.suspiciousIPs?.length > 0 ? liveSummary.suspiciousIPs : [];
  const liveDisplayLogs          = hasRealData ? liveLogs : [];
  const liveDisplayTopRules      = hasRealData && liveSummary?.topRules ? liveSummary.topRules : [];
  const liveDisplayMetadata      = hasRealData && liveSummary ? liveSummary.metadata : {
    datasetName: null,
    isSample: false,
    rowsProcessed: 0,
    alertsDetected: 0,
  };

  // Active dataset — switches cleanly between modes with no cross-contamination
  const currentSummaryStats  = isLiveMode ? liveDisplaySummaryStats  : demoSummaryStats;
  const currentActivityData  = isLiveMode ? liveDisplayActivityData  : demoActivityData;
  const currentSeverityData  = isLiveMode ? liveDisplaySeverityData  : demoSeverityData;
  const currentAlerts        = isLiveMode ? liveDisplayAlerts        : demoRecentAlerts;
  const currentSuspiciousIPs = isLiveMode ? liveDisplaySuspiciousIPs : demoSuspiciousIPs;
  const currentLogs          = isLiveMode ? liveDisplayLogs          : demoLogEntries;
  const currentTopRules      = isLiveMode ? liveDisplayTopRules      : [];
  const currentMetadata      = isLiveMode
    ? liveDisplayMetadata
    : { datasetName: 'Static Demo Data', isSample: true, rowsProcessed: 14872, alertsDetected: 342 };

  const value = {
    // Mode
    appMode,
    setAppMode,
    isLiveMode,
    isDemoMode,

    // Legacy alias kept so existing pages that read `dataMode` don't break
    dataMode:    appMode === 'live' ? 'backend' : 'demo',
    setDataMode: (m) => setAppMode(m === 'backend' ? 'live' : 'demo'),

    // Connectivity
    backendStatus,
    engineInfo,
    isLoading,
    apiError,

    // isUsingBackend: true only when live + connected + real data present
    isUsingBackend,
    // hasRealData: whether a real (non-sample) dataset has been uploaded
    hasRealData,

    // Backend upload availability. isReadOnly is true whenever the backend refuses writes
    // (emergency read-only switch); it stays false while the backend is still unknown/unreachable.
    uploadsEnabled,
    isReadOnly: engineInfo ? !uploadsEnabled : false,
    // Per-visitor private sessions (public deployment) and the limits the backend advertises
    isSessionMode,
    maxUploadBytes,
    maxUploadRows: engineInfo?.limits?.max_upload_rows ?? null,
    sessionIdleMinutes: engineInfo?.limits?.session_idle_timeout_minutes ?? null,
    sessionNotice,
    clearSessionNotice: () => setSessionNotice(null),

    // Active display data (mode-resolved)
    summaryStats:  currentSummaryStats,
    activityData:  currentActivityData,
    severityData:  currentSeverityData,
    alerts:        currentAlerts,
    suspiciousIPs: currentSuspiciousIPs,
    logs:          currentLogs,
    metadata:      currentMetadata,
    topRules:      currentTopRules,

    // Actions
    uploading,
    uploadError,
    uploadResult,
    handleUploadCsv,
    handleResetSample,
    refreshBackend:    loadBackendData,
    clearUploadError:  () => setUploadError(null),
    clearUploadResult: () => setUploadResult(null),
  };

  return (
    <ThreatLensContext.Provider value={value}>
      {children}
    </ThreatLensContext.Provider>
  );
}

// oxlint-disable-next-line react/only-export-components
export function useThreatLens() {
  const ctx = useContext(ThreatLensContext);
  if (!ctx) {
    throw new Error('useThreatLens must be used within a ThreatLensProvider');
  }
  return ctx;
}
