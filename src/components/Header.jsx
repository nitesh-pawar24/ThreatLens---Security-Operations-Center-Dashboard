/**
 * ThreatLens – Top Header
 * ========================
 * Contains the page title, LIVE / DEMO mode switcher, and backend status pill.
 *
 * LIVE MODE (green):  Displays real data uploaded by the user. No demo data shown.
 * DEMO MODE (blue):   Displays static sample data for exploration. Backend not queried.
 */

import { Radio, Database, RefreshCw, WifiOff, Wifi } from 'lucide-react';
import { useThreatLens } from '../context/ThreatLensContext';
import { API_BASE_URL } from '../services/api';

const PAGE_TITLES = {
  overview:      'Overview',
  alerts:        'Alerts',
  logs:          'Log Analysis',
  'ip-activity': 'IP Activity',
  settings:      'Settings',
};

export default function Header({ activePage }) {
  const {
    appMode,
    setAppMode,
    backendStatus,
    isLoading,
    hasRealData,
    metadata,
    refreshBackend,
    isReadOnly,
  } = useThreatLens();

  const isLive = appMode === 'live';

  return (
    <header className="header">
      <h1 className="header-title">{PAGE_TITLES[activePage] ?? activePage}</h1>

      <div className="header-right">

        {/* ── Mode Switcher ──────────────────────────────────────────────── */}
        <div
          className="mode-switcher"
          role="group"
          aria-label="Select application mode"
          style={{
            display: 'flex',
            alignItems: 'center',
            background: 'var(--bg-base)',
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius-sm)',
            padding: '2px',
            gap: '2px',
          }}
        >
          {/* LIVE MODE button */}
          <button
            type="button"
            className={`mode-btn ${isLive ? 'active' : ''}`}
            onClick={() => setAppMode('live')}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 5,
              background: isLive ? 'rgba(34, 197, 94, 0.18)' : 'transparent',
              color: isLive ? '#4ade80' : 'var(--text-muted)',
              border: isLive ? '1px solid rgba(34, 197, 94, 0.35)' : '1px solid transparent',
              borderRadius: 3,
              padding: '4px 10px',
              fontSize: 11,
              fontWeight: 700,
              cursor: 'pointer',
              transition: 'all 0.15s ease',
              letterSpacing: '0.03em',
            }}
            title="Live Mode — shows only real uploaded log data. Never uses demo data."
          >
            {/* Pulsing dot for live mode */}
            {isLive && (
              <span
                style={{
                  width: 7,
                  height: 7,
                  borderRadius: '50%',
                  background: '#22c55e',
                  boxShadow: '0 0 6px #22c55e',
                  display: 'inline-block',
                  flexShrink: 0,
                }}
                aria-hidden="true"
              />
            )}
            {!isLive && <Radio size={12} aria-hidden="true" />}
            LIVE MODE
          </button>

          {/* DEMO MODE button */}
          <button
            type="button"
            className={`mode-btn ${!isLive ? 'active' : ''}`}
            onClick={() => setAppMode('demo')}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 5,
              background: !isLive ? 'rgba(59, 130, 246, 0.15)' : 'transparent',
              color: !isLive ? '#93c5fd' : 'var(--text-muted)',
              border: !isLive ? '1px solid rgba(59, 130, 246, 0.3)' : '1px solid transparent',
              borderRadius: 3,
              padding: '4px 10px',
              fontSize: 11,
              fontWeight: 700,
              cursor: 'pointer',
              transition: 'all 0.15s ease',
              letterSpacing: '0.03em',
            }}
            title="Demo Mode — shows static sample data. Safe for exploration."
          >
            <Database size={12} aria-hidden="true" />
            DEMO MODE
          </button>
        </div>

        {/* ── Backend Status Pill ───────────────────────────────────────── */}
        {isLive && backendStatus === 'connected' && hasRealData && (
          <div
            className="sys-status"
            aria-label={`Backend connected — dataset: ${metadata?.datasetName || 'uploaded'}`}
            style={{
              background: 'rgba(34, 197, 94, 0.1)',
              border: '1px solid rgba(34, 197, 94, 0.3)',
              borderRadius: 'var(--radius-sm)',
              padding: '4px 10px',
              fontSize: 11,
              color: '#4ade80',
              display: 'flex',
              alignItems: 'center',
              gap: 6,
            }}
          >
            <div
              className="sys-status-dot"
              style={{ background: '#22c55e', boxShadow: '0 0 6px #22c55e' }}
              aria-hidden="true"
            />
            <Wifi size={11} aria-hidden="true" />
            <span>Backend: Online</span>
            <span style={{ color: 'var(--text-muted)', fontSize: 10 }}>
              • {metadata?.datasetName || 'active log'}
            </span>
          </div>
        )}

        {isLive && backendStatus === 'connected' && !hasRealData && (
          <div
            className="sys-status"
            aria-label={isReadOnly ? "Public Demo (Read-Only Mode)" : "Backend connected — no real data uploaded yet"}
            title={
              isReadOnly
                ? "Public Portfolio Instance: Live log uploads are disabled to preserve visitor privacy. Switch to DEMO MODE to explore all interactive features, or run locally."
                : "FastAPI backend running locally and ready for CSV log ingestion."
            }
            style={{
              background: isReadOnly ? 'rgba(59, 130, 246, 0.08)' : 'rgba(234, 179, 8, 0.08)',
              border: isReadOnly ? '1px solid rgba(59, 130, 246, 0.25)' : '1px solid rgba(234, 179, 8, 0.25)',
              borderRadius: 'var(--radius-sm)',
              padding: '4px 10px',
              fontSize: 11,
              color: isReadOnly ? '#93c5fd' : '#fbbf24',
              display: 'flex',
              alignItems: 'center',
              gap: 6,
            }}
          >
            <div
              className="sys-status-dot"
              style={{ background: isReadOnly ? '#3b82f6' : '#d97706' }}
              aria-hidden="true"
            />
            <span>{isReadOnly ? 'Public Demo: Read-Only' : 'Backend: Connected — Awaiting Upload'}</span>
          </div>
        )}

        {isLive && backendStatus === 'disconnected' && (
          <div
            className="sys-status"
            aria-label="Backend offline — upload not available"
            style={{
              background: 'rgba(239, 68, 68, 0.1)',
              border: '1px solid rgba(239, 68, 68, 0.3)',
              borderRadius: 'var(--radius-sm)',
              padding: '4px 10px',
              fontSize: 11,
              color: '#f87171',
              display: 'flex',
              alignItems: 'center',
              gap: 6,
            }}
          >
            <div
              className="sys-status-dot"
              style={{ background: '#ef4444', boxShadow: '0 0 6px #ef4444' }}
              aria-hidden="true"
            />
            <WifiOff size={11} aria-hidden="true" />
            <span>Backend: Offline</span>
            <button
              type="button"
              onClick={refreshBackend}
              disabled={isLoading}
              style={{
                background: 'none',
                border: 'none',
                color: '#f87171',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                padding: 0,
                marginLeft: 4,
              }}
              title={`Retry connection to backend (${API_BASE_URL || 'http://localhost:8000'})`}
              aria-label="Retry backend connection"
            >
              <RefreshCw size={12} className={isLoading ? 'spin-icon' : ''} aria-hidden="true" />
            </button>
          </div>
        )}

        {isLive && backendStatus === 'checking' && (
          <div
            className="sys-status"
            style={{
              background: 'rgba(148, 163, 184, 0.08)',
              border: '1px solid rgba(148, 163, 184, 0.2)',
              borderRadius: 'var(--radius-sm)',
              padding: '4px 10px',
              fontSize: 11,
              color: 'var(--text-muted)',
              display: 'flex',
              alignItems: 'center',
              gap: 6,
            }}
          >
            <RefreshCw size={11} className="spin-icon" aria-hidden="true" />
            <span>Connecting…</span>
          </div>
        )}

        {!isLive && (
          <div
            className="demo-badge"
            role="status"
            aria-label="Demo mode — all data is simulated"
            title="All data displayed is simulated and does not reflect any real network or system"
          >
            <span className="demo-badge-dot" aria-hidden="true" />
            Demo Data Active
          </div>
        )}
      </div>
    </header>
  );
}
