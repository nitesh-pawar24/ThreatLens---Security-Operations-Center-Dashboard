/**
 * Settings page – Configuration, detection rule thresholds,
 * and engine status display.
 *
 * Phase 6: Includes interactive Detection Configuration panel allowing
 * tuning of brute-force thresholds, correlation windows, and deduplication settings.
 */

import { useState, useEffect, useCallback } from 'react';
import {
  Info, Lock, Sliders,
  Save, RotateCcw, Check, AlertCircle, RefreshCw,
} from 'lucide-react';
import { useThreatLens } from '../context/ThreatLensContext';
import { DEMO_NOTICE } from '../data/demoData';
import { getDetectionConfig, updateDetectionConfig, API_BASE_URL } from '../services/api';

export default function SettingsPage() {
  const { isLiveMode, backendStatus, isUsingBackend, metadata, isReadOnly } = useThreatLens();

  // Config state
  const [config, setConfig] = useState(null);
  const [defaults, setDefaults] = useState(null);
  const [loadingConfig, setLoadingConfig] = useState(false);
  const [savingConfig, setSavingConfig] = useState(false);
  const [feedback, setFeedback] = useState(null); // { type: 'success' | 'error', message: string }

  // Load config from backend
  const loadConfig = useCallback(async () => {
    if (!isUsingBackend) return;
    setLoadingConfig(true);
    try {
      const res = await getDetectionConfig();
      setConfig(res.config);
      setDefaults(res.defaults);
    } catch (err) {
      console.warn('Failed to load detection config:', err.message);
    } finally {
      setLoadingConfig(false);
    }
  }, [isUsingBackend]);

  useEffect(() => {
    if (isUsingBackend) {
      // oxlint-disable-next-line react/set-state-in-effect
      loadConfig();
    }
  }, [isUsingBackend, loadConfig]);

  const handleFieldChange = (key, value) => {
    const num = parseInt(value, 10);
    setConfig((prev) => ({
      ...prev,
      [key]: isNaN(num) ? value : num,
    }));
  };

  const handleSave = async (e) => {
    e.preventDefault();
    setSavingConfig(true);
    setFeedback(null);

    // Client-side validation
    const errors = [];
    if (config.brute_force_threshold < 1) errors.push('Failed-logon threshold must be at least 1.');
    if (config.brute_force_window_seconds < 10) errors.push('Brute-force window must be at least 10 seconds.');
    if (config.account_brute_force_threshold < 1) errors.push('Account brute-force threshold must be at least 1.');
    if (config.account_brute_force_window_seconds < 10) errors.push('Account brute-force window must be at least 10 seconds.');
    if (config.port_scan_threshold < 1) errors.push('Port scan threshold must be at least 1.');
    if (config.dedup_window_seconds < 0) errors.push('Deduplication window must be 0 or positive.');

    if (errors.length > 0) {
      setFeedback({ type: 'error', message: errors[0] });
      setSavingConfig(false);
      return;
    }

    try {
      const res = await updateDetectionConfig(config);
      setConfig(res.config);
      setFeedback({
        type: 'success',
        message: 'Detection thresholds updated successfully. New settings will apply to subsequent log analyses.',
      });
      setTimeout(() => setFeedback(null), 5000);
    } catch (err) {
      setFeedback({ type: 'error', message: err.message || 'Failed to update detection thresholds.' });
    } finally {
      setSavingConfig(false);
    }
  };

  const handleResetDefaults = () => {
    if (!defaults) return;
    setConfig({ ...defaults });
    setFeedback({
      type: 'success',
      message: 'Restored factory default thresholds. Click "Save Changes" to apply.',
    });
    setTimeout(() => setFeedback(null), 4000);
  };

  return (
    <div className="page-content">
      {/* Notice bar */}
      <div className="demo-notice-bar" role="note">
        <Info size={16} style={{ flexShrink: 0, marginTop: 2 }} aria-hidden="true" />
        <span>
          {isLiveMode
            ? (isUsingBackend
                ? 'Connected to local FastAPI backend. Tunable detection settings apply to local analysis in memory.'
                : 'Live Mode active. Connect to the backend and upload a CSV to enable tunable detection settings.')
            : `${DEMO_NOTICE} Settings shown below reflect simulated defaults.`}
        </span>
      </div>

      <div className="settings-grid" style={{ maxWidth: 840 }}>
        {/* Detection Rule Configuration (Phase 6) */}
        {isUsingBackend && (
          <div className="config-group">
            <div className="config-group-title">
              <Sliders size={16} color="var(--accent)" aria-hidden="true" />
              <span>Tunable Detection Thresholds & Windows</span>
            </div>
            <div className="config-group-desc">
              Configure detection sensitivities, correlation time windows, and deduplication bounds.
              Threshold changes are stored in memory and take effect on your next CSV analysis.
            </div>

            {isReadOnly && (
              <div style={{
                margin: '12px 0',
                padding: '10px 14px',
                background: 'rgba(59, 130, 246, 0.08)',
                border: '1px solid rgba(59, 130, 246, 0.25)',
                borderRadius: 'var(--radius-sm)',
                fontSize: 12,
                color: '#93c5fd',
                display: 'flex',
                gap: 8,
                alignItems: 'center',
              }}>
                <Lock size={15} color="#60a5fa" style={{ flexShrink: 0 }} />
                <span>
                  <strong>Portfolio Read-Only Mode:</strong> Threshold modifications are disabled on this shared public demonstration instance. Clone and run ThreatLens locally to customize SOC detection rules.
                </span>
              </div>
            )}

            {loadingConfig ? (
              <div style={{ padding: 20, textAlign: 'center', color: 'var(--text-muted)', fontSize: 13 }}>
                <RefreshCw size={14} className="spin-icon" style={{ marginRight: 6 }} />
                Loading detection configuration…
              </div>
            ) : config ? (
              <form onSubmit={handleSave}>
                <div className="config-form-grid">
                  {/* IP Brute Force Threshold */}
                  <div className="config-card">
                    <div className="config-card-header">
                      <div className="config-card-label">IP Brute-Force Threshold</div>
                      <div className="config-card-help">Minimum failed logons from the same IP to trigger an alert.</div>
                    </div>
                    <div className="config-input-row">
                      <input
                        type="number"
                        min="1"
                        max="1000"
                        className="config-input"
                        value={config.brute_force_threshold ?? 5}
                        onChange={(e) => handleFieldChange('brute_force_threshold', e.target.value)}
                      />
                      <span className="config-unit">events</span>
                      <span className="config-default-tag">Def: 5</span>
                    </div>
                  </div>

                  {/* IP Brute Force Window */}
                  <div className="config-card">
                    <div className="config-card-header">
                      <div className="config-card-label">IP Brute-Force Window</div>
                      <div className="config-card-help">Maximum duration between first and last failed logon to correlate.</div>
                    </div>
                    <div className="config-input-row">
                      <input
                        type="number"
                        min="10"
                        max="86400"
                        className="config-input"
                        value={config.brute_force_window_seconds ?? 60}
                        onChange={(e) => handleFieldChange('brute_force_window_seconds', e.target.value)}
                      />
                      <span className="config-unit">seconds</span>
                      <span className="config-default-tag">Def: 60s</span>
                    </div>
                  </div>

                  {/* Account Brute Force Threshold */}
                  <div className="config-card">
                    <div className="config-card-header">
                      <div className="config-card-label">Account Brute-Force Threshold</div>
                      <div className="config-card-help">Failures targeting the same username across potentially multiple IPs.</div>
                    </div>
                    <div className="config-input-row">
                      <input
                        type="number"
                        min="1"
                        max="1000"
                        className="config-input"
                        value={config.account_brute_force_threshold ?? 5}
                        onChange={(e) => handleFieldChange('account_brute_force_threshold', e.target.value)}
                      />
                      <span className="config-unit">events</span>
                      <span className="config-default-tag">Def: 5</span>
                    </div>
                  </div>

                  {/* Account Brute Force Window */}
                  <div className="config-card">
                    <div className="config-card-header">
                      <div className="config-card-label">Account Brute-Force Window</div>
                      <div className="config-card-help">Time window to detect targeted password spraying or credential stuffing.</div>
                    </div>
                    <div className="config-input-row">
                      <input
                        type="number"
                        min="10"
                        max="86400"
                        className="config-input"
                        value={config.account_brute_force_window_seconds ?? 60}
                        onChange={(e) => handleFieldChange('account_brute_force_window_seconds', e.target.value)}
                      />
                      <span className="config-unit">seconds</span>
                      <span className="config-default-tag">Def: 60s</span>
                    </div>
                  </div>

                  {/* Port Scan Threshold */}
                  <div className="config-card">
                    <div className="config-card-header">
                      <div className="config-card-label">Port Scan Threshold</div>
                      <div className="config-card-help">Minimum port scan events from the same source address.</div>
                    </div>
                    <div className="config-input-row">
                      <input
                        type="number"
                        min="1"
                        max="1000"
                        className="config-input"
                        value={config.port_scan_threshold ?? 3}
                        onChange={(e) => handleFieldChange('port_scan_threshold', e.target.value)}
                      />
                      <span className="config-unit">events</span>
                      <span className="config-default-tag">Def: 3</span>
                    </div>
                  </div>

                  {/* Port Scan Window */}
                  <div className="config-card">
                    <div className="config-card-header">
                      <div className="config-card-label">Port Scan Window</div>
                      <div className="config-card-help">Sliding window for correlated port sweep events.</div>
                    </div>
                    <div className="config-input-row">
                      <input
                        type="number"
                        min="10"
                        max="86400"
                        className="config-input"
                        value={config.port_scan_window_seconds ?? 60}
                        onChange={(e) => handleFieldChange('port_scan_window_seconds', e.target.value)}
                      />
                      <span className="config-unit">seconds</span>
                      <span className="config-default-tag">Def: 60s</span>
                    </div>
                  </div>

                  {/* Repeated Connection Threshold */}
                  <div className="config-card">
                    <div className="config-card-header">
                      <div className="config-card-label">Repeated Connect Threshold</div>
                      <div className="config-card-help">High-frequency connection attempts from the same source IP.</div>
                    </div>
                    <div className="config-input-row">
                      <input
                        type="number"
                        min="1"
                        max="1000"
                        className="config-input"
                        value={config.repeated_connect_threshold ?? 10}
                        onChange={(e) => handleFieldChange('repeated_connect_threshold', e.target.value)}
                      />
                      <span className="config-unit">events</span>
                      <span className="config-default-tag">Def: 10</span>
                    </div>
                  </div>

                  {/* Repeated Connection Window */}
                  <div className="config-card">
                    <div className="config-card-header">
                      <div className="config-card-label">Repeated Connect Window</div>
                      <div className="config-card-help">Window in seconds for repeated connection burst detection.</div>
                    </div>
                    <div className="config-input-row">
                      <input
                        type="number"
                        min="10"
                        max="86400"
                        className="config-input"
                        value={config.repeated_connect_window_seconds ?? 120}
                        onChange={(e) => handleFieldChange('repeated_connect_window_seconds', e.target.value)}
                      />
                      <span className="config-unit">seconds</span>
                      <span className="config-default-tag">Def: 120s</span>
                    </div>
                  </div>

                  {/* Account Lifecycle Window */}
                  <div className="config-card">
                    <div className="config-card-header">
                      <div className="config-card-label">Account Lifecycle Window</div>
                      <div className="config-card-help">Window between account creation and rapid privilege escalation / group add.</div>
                    </div>
                    <div className="config-input-row">
                      <input
                        type="number"
                        min="10"
                        max="86400"
                        className="config-input"
                        value={config.account_lifecycle_window_seconds ?? 900}
                        onChange={(e) => handleFieldChange('account_lifecycle_window_seconds', e.target.value)}
                      />
                      <span className="config-unit">seconds</span>
                      <span className="config-default-tag">Def: 900s</span>
                    </div>
                  </div>

                  {/* Multi-Account Changes Threshold */}
                  <div className="config-card">
                    <div className="config-card-header">
                      <div className="config-card-label">Multi-Account Changes Threshold</div>
                      <div className="config-card-help">Multiple distinct user management events in rapid succession.</div>
                    </div>
                    <div className="config-input-row">
                      <input
                        type="number"
                        min="1"
                        max="100"
                        className="config-input"
                        value={config.multi_account_changes_threshold ?? 3}
                        onChange={(e) => handleFieldChange('multi_account_changes_threshold', e.target.value)}
                      />
                      <span className="config-unit">events</span>
                      <span className="config-default-tag">Def: 3</span>
                    </div>
                  </div>

                  {/* Deduplication Window */}
                  <div className="config-card">
                    <div className="config-card-header">
                      <div className="config-card-label">Alert Deduplication Window</div>
                      <div className="config-card-help">Fingerprint-based deduplication window collapsing identical alert patterns.</div>
                    </div>
                    <div className="config-input-row">
                      <input
                        type="number"
                        min="0"
                        max="86400"
                        className="config-input"
                        value={config.dedup_window_seconds ?? 3600}
                        onChange={(e) => handleFieldChange('dedup_window_seconds', e.target.value)}
                      />
                      <span className="config-unit">seconds</span>
                      <span className="config-default-tag">Def: 3600s</span>
                    </div>
                  </div>
                </div>

                {/* Feedback message */}
                {feedback && (
                  <div
                    style={{
                      marginTop: 14,
                      padding: '8px 12px',
                      borderRadius: 'var(--radius-sm)',
                      fontSize: 12,
                      display: 'flex',
                      alignItems: 'center',
                      gap: 8,
                      background: feedback.type === 'error' ? 'rgba(239, 68, 68, 0.12)' : 'rgba(34, 197, 94, 0.12)',
                      border: `1px solid ${feedback.type === 'error' ? 'rgba(239, 68, 68, 0.3)' : 'rgba(34, 197, 94, 0.3)'}`,
                      color: feedback.type === 'error' ? '#f87171' : '#4ade80',
                    }}
                  >
                    {feedback.type === 'error' ? <AlertCircle size={14} /> : <Check size={14} />}
                    <span>{feedback.message}</span>
                  </div>
                )}

                {/* Action buttons */}
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 16 }}>
                  <button
                    type="submit"
                    className="btn btn-primary"
                    disabled={savingConfig || isReadOnly}
                    style={{ fontSize: 12, opacity: isReadOnly ? 0.6 : 1 }}
                    title={isReadOnly ? "Modifying thresholds is disabled in public read-only mode" : undefined}
                  >
                    <Save size={13} />
                    {isReadOnly ? 'Thresholds Locked (Public Demo)' : savingConfig ? 'Saving…' : 'Save Changes'}
                  </button>

                  <button
                    type="button"
                    className="btn btn-secondary"
                    onClick={handleResetDefaults}
                    disabled={savingConfig || isReadOnly}
                    style={{ fontSize: 12, opacity: isReadOnly ? 0.6 : 1 }}
                    title={isReadOnly ? "Resetting defaults is disabled in public read-only mode" : undefined}
                  >
                    <RotateCcw size={13} />
                    Reset to Defaults
                  </button>
                </div>

                <div style={{ marginTop: 12, fontSize: 11, color: 'var(--text-muted)', fontStyle: 'italic' }}>
                  * In-memory configuration: settings reset to defaults when the FastAPI backend process restarts.
                </div>
              </form>
            ) : null}
          </div>
        )}

        {/* General */}
        <div className="settings-group">
          <div className="settings-group-title">General</div>
          <div className="settings-row">
            <div>
              <div className="settings-row-label">Application Name</div>
              <div className="settings-row-desc">ThreatLens Security Operations Center</div>
            </div>
            <span className="settings-value">ThreatLens</span>
          </div>
          <div className="settings-row">
            <div>
              <div className="settings-row-label">Version</div>
              <div className="settings-row-desc">Current system release</div>
            </div>
            <span className="settings-value">ThreatLens v1.0</span>
          </div>
          <div className="settings-row">
            <div>
              <div className="settings-row-label">Stack</div>
              <div className="settings-row-desc">Frontend & Backend architectures</div>
            </div>
            <span className="settings-value">React 19 + FastAPI + Pandas</span>
          </div>
        </div>

        {/* Data & Backend Engine */}
        <div className="settings-group">
          <div className="settings-group-title">Detection Engine & API</div>
          <div className="settings-row">
            <div>
              <div className="settings-row-label">Data Mode</div>
              <div className="settings-row-desc">Currently active data source</div>
            </div>
            <span className="settings-value" style={{ color: isLiveMode ? '#4ade80' : '#93c5fd' }}>
              {isLiveMode ? (isUsingBackend ? 'Live Mode — FastAPI Detection Engine' : 'Live Mode — Awaiting Upload') : 'Demo Mode — Simulated Data'}
            </span>
          </div>
          <div className="settings-row">
            <div>
              <div className="settings-row-label">API Status</div>
              <div className="settings-row-desc">Local Python backend health</div>
            </div>
            <span className="settings-value" style={{ color: backendStatus === 'connected' ? '#4ade80' : '#f87171' }}>
              {backendStatus === 'connected' ? `Connected (${API_BASE_URL || 'http://127.0.0.1:8000'})` : 'Disconnected'}
            </span>
          </div>
          <div className="settings-row">
            <div>
              <div className="settings-row-label">Active Dataset</div>
              <div className="settings-row-desc">Current CSV log analyzed</div>
            </div>
            <span className="settings-value">
              {metadata?.datasetName || 'sample_logs.csv'}
            </span>
          </div>
          <div className="settings-row">
            <div>
              <div className="settings-row-label">Detection Rules</div>
              <div className="settings-row-desc">Transparent correlation & lifecycle rules</div>
            </div>
            <span className="settings-value" style={{ fontSize: 11 }}>
              14 rules (BruteForce, AccountBruteForce, LogonAfterBruteForce, AccountLifecycle, MultiAccountChanges, AuditLogCleared, etc.)
            </span>
          </div>
          <div className="settings-row">
            <div>
              <div className="settings-row-label">Prioritization Model</div>
              <div className="settings-row-desc">Deterministic 0–100 risk scoring algorithm</div>
            </div>
            <span className="settings-value" style={{ fontSize: 11 }}>
              Transparent (Severity + Evidence Bonus + Correlation Bonus)
            </span>
          </div>
        </div>

        {/* Display */}
        <div className="settings-group">
          <div className="settings-group-title">Display & Visualization</div>
          <div className="settings-row">
            <div>
              <div className="settings-row-label">Theme</div>
              <div className="settings-row-desc">Colour scheme applied to all views</div>
            </div>
            <span className="settings-value">Dark Navy SOC</span>
          </div>
          <div className="settings-row">
            <div>
              <div className="settings-row-label">Visualizations</div>
              <div className="settings-row-desc">Timeline charts & severity distributions</div>
            </div>
            <span className="settings-value">Recharts 2.x</span>
          </div>
          <div className="settings-row">
            <div>
              <div className="settings-row-label">Network Scope</div>
              <div className="settings-row-desc">Simulated and RFC 5737 documentation IPs only</div>
            </div>
            <span className="settings-value">192.0.2.x / 198.51.100.x / 203.0.113.x</span>
          </div>
        </div>

        {/* Safety notice */}
        <div
          style={{
            background: 'rgba(59,130,246,0.05)',
            border: '1px solid rgba(59,130,246,0.15)',
            borderRadius: 'var(--radius-md)',
            padding: 'var(--space-md) var(--space-lg)',
            display: 'flex',
            gap: 'var(--space-sm)',
            fontSize: 12,
            color: 'var(--text-secondary)',
          }}
        >
          <Lock size={16} style={{ flexShrink: 0, marginTop: 2, color: 'var(--accent)' }} aria-hidden="true" />
          <span>
            ThreatLens runs entirely locally as independent frontend (Vite) and backend (FastAPI) processes.
            It does <strong>not</strong> perform network scanning, live packet capture, external IP lookups,
            or telemetry. Uploaded CSV logs remain strictly in local memory and are never transmitted externally.
          </span>
        </div>
      </div>
    </div>
  );
}
