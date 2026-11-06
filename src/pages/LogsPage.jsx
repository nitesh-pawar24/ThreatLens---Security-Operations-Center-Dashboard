/**
 * ThreatLens – Log Analysis Page
 * ================================
 * CSV Log Upload, Rule Detection Engine Trigger, Windows Event Viewer Importer,
 * and Interactive SOC Log Viewer.
 */

import { useState, useRef } from 'react';
import {
  UploadCloud, FileText, CheckCircle2, AlertTriangle, RefreshCw,
  Search, Filter, Terminal, X, Info, Server,
  Monitor, Shield, ChevronDown, ChevronUp, FileSpreadsheet, Lock,
} from 'lucide-react';
import { useThreatLens } from '../context/ThreatLensContext';
import { DEMO_NOTICE } from '../data/demoData';
import { SeverityBadge } from '../components/Badges';

const LEVEL_CLASS = {
  CRITICAL: 'level-critical',
  ERROR:    'level-error',
  WARN:     'level-warn',
  INFO:     'level-info',
};

const SUPPORTED_WINDOWS_EVENTS = [
  { id: 4624, name: 'Successful Logon', type: 'LOGIN_SUCCESS' },
  { id: 4625, name: 'Failed Logon', type: 'LOGIN_FAILURE' },
  { id: 4634, name: 'Logoff', type: 'LOGOFF' },
  { id: 4648, name: 'Explicit Creds Logon', type: 'EXPLICIT_CRED_LOGON' },
  { id: 4672, name: 'Special Privileges Assigned', type: 'PRIVILEGE_ESCALATION' },
  { id: 4688, name: 'Process Created', type: 'PROCESS_CREATED' },
  { id: 4720, name: 'Account Created', type: 'ACCOUNT_CREATED' },
  { id: 4726, name: 'Account Deleted', type: 'ACCOUNT_DELETED' },
  { id: 4732, name: 'Group Member Added', type: 'GROUP_MEMBER_ADDED' },
  { id: 1102, name: 'Audit Log Cleared', type: 'AUDIT_LOG_CLEARED' },
];

export default function LogsPage() {
  const {
    logs,
    alerts,
    isUsingBackend,
    isLiveMode,
    isReadOnly,
    isSessionMode,
    maxUploadBytes,
    sessionIdleMinutes,
    hasRealData,
    backendStatus,
    metadata,
    uploading,
    uploadError,
    uploadResult,
    handleUploadCsv,
    handleResetSample,
    clearUploadError,
    clearUploadResult,
  } = useThreatLens();

  const [search, setSearch]                   = useState('');
  const [level, setLevel]                     = useState('All');
  const [importFormat, setImportFormat]       = useState('windows'); // 'windows' | 'standard'
  const [selectedFile, setSelectedFile]       = useState(null);
  const [dragActive, setDragActive]           = useState(false);
  const [localClientError, setLocalClientError] = useState(null);
  const [expandedLogIds, setExpandedLogIds]   = useState(new Set());
  const fileInputRef = useRef(null);

  // Toggle log description expansion
  const toggleExpand = (id) => {
    setExpandedLogIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  // File selection
  const onFileChange = (e) => {
    setLocalClientError(null);
    clearUploadError();
    clearUploadResult();
    const file = e.target.files?.[0];
    if (file) {
      if (!file.name.toLowerCase().endsWith('.csv')) {
        setLocalClientError('Invalid file type. Please select a CSV file (.csv).');
        setSelectedFile(null);
        return;
      }
      if (file.size === 0) {
        setLocalClientError('The selected file is empty. Please choose a non-empty CSV file.');
        setSelectedFile(null);
        return;
      }
      if (file.size > maxUploadBytes) {
        const limitMb = maxUploadBytes / (1024 * 1024);
        const fileMb  = (file.size / (1024 * 1024)).toFixed(1);
        setLocalClientError(`File too large (${fileMb} MB). Maximum allowed size is ${limitMb} MB.`);
        setSelectedFile(null);
        return;
      }
      setSelectedFile(file);
    }
  };

  // Drag and drop handlers
  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    setLocalClientError(null);
    clearUploadError();
    clearUploadResult();

    const file = e.dataTransfer.files?.[0];
    if (file) {
      if (!file.name.toLowerCase().endsWith('.csv')) {
        setLocalClientError('Invalid file type. Please upload a CSV file (.csv).');
        setSelectedFile(null);
        return;
      }
      if (file.size === 0) {
        setLocalClientError('The dropped file is empty. Please choose a non-empty CSV file.');
        setSelectedFile(null);
        return;
      }
      if (file.size > maxUploadBytes) {
        const limitMb = maxUploadBytes / (1024 * 1024);
        const fileMb  = (file.size / (1024 * 1024)).toFixed(1);
        setLocalClientError(`File too large (${fileMb} MB). Maximum allowed size is ${limitMb} MB.`);
        setSelectedFile(null);
        return;
      }
      setSelectedFile(file);
    }
  };

  // Trigger upload
  const triggerUpload = async () => {
    if (!selectedFile) return;
    try {
      await handleUploadCsv(selectedFile, { format: importFormat });
      setSelectedFile(null);
      if (fileInputRef.current) fileInputRef.current.value = '';
    } catch {
      // Error handled in context state
    }
  };

  // Filter logs for the viewer
  const filteredLogs = logs.filter((e) => {
    const q = search.toLowerCase();
    const msg = e.message || '';
    const src = e.source || '';
    const id = e.id || '';
    const eventType = e.event_type || '';
    const user = e.username || '';
    const winEid = e.win_event_id ? String(e.win_event_id) : '';
    const winComputer = e.win_computer || '';
    const winLabel = e.win_label || '';

    const matchSearch =
      !q ||
      msg.toLowerCase().includes(q) ||
      src.toLowerCase().includes(q) ||
      id.toLowerCase().includes(q) ||
      eventType.toLowerCase().includes(q) ||
      user.toLowerCase().includes(q) ||
      winEid.includes(q) ||
      winComputer.toLowerCase().includes(q) ||
      winLabel.toLowerCase().includes(q);

    const matchLevel = level === 'All' || e.level === level;
    return matchSearch && matchLevel;
  });

  return (
    <div className="page-content">
      {/* Notice bar — mode-aware */}
      {isLiveMode ? (
        hasRealData ? (
          <div
            className="demo-notice-bar"
            role="note"
            style={{ background: 'rgba(34,197,94,0.08)', border: '1px solid rgba(34,197,94,0.2)', color: '#4ade80' }}
          >
            <Server size={16} style={{ flexShrink: 0, marginTop: 2 }} aria-hidden="true" />
            <span>
              <strong>FastAPI Detection Engine Active:</strong> Analyzing{' '}
              <code>{metadata?.datasetName || 'uploaded file'}</code>{' '}
              {metadata?.logFormat === 'windows_event_viewer' && (
                <span style={{ marginLeft: 6, padding: '2px 6px', background: 'rgba(34,197,94,0.2)', borderRadius: 3, fontSize: 11 }}>
                  Windows Security Event Log Mode
                </span>
              )}
            </span>
          </div>
        ) : backendStatus === 'disconnected' ? (
          <div
            className="demo-notice-bar"
            role="alert"
            style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)', color: '#f87171' }}
          >
            <Info size={16} style={{ flexShrink: 0, marginTop: 2 }} aria-hidden="true" />
            <span><strong>Backend Offline:</strong> Cannot connect to the FastAPI backend. Start the backend server and retry.</span>
          </div>
        ) : (
          <div
            className="demo-notice-bar"
            role="note"
            style={{ background: 'rgba(234,179,8,0.06)', border: '1px solid rgba(234,179,8,0.2)', color: '#fbbf24' }}
          >
            <UploadCloud size={16} style={{ flexShrink: 0, marginTop: 2 }} aria-hidden="true" />
            <span>
              <strong>Live Mode — Ready:</strong>{' '}
              {isReadOnly
                ? 'Public cloud instance is in portfolio read-only mode to preserve visitor privacy. Switch to Demo Mode above to explore all features.'
                : isSessionMode
                  ? `Upload a supported CSV file below to begin analysis. Your upload is private to this browser session${sessionIdleMinutes ? ` and is cleared after ${sessionIdleMinutes} minutes of inactivity` : ''}.`
                  : 'Upload a supported CSV file below to begin analysis.'}
            </span>
          </div>
        )
      ) : (
        <div className="demo-notice-bar" role="note">
          <Info size={16} style={{ flexShrink: 0, marginTop: 2 }} aria-hidden="true" />
          <span>{DEMO_NOTICE} (Switch to Live Mode to upload and analyze real security logs).</span>
        </div>
      )}

      {/* ── CSV Upload & Detection Engine Panel ───────────────────────── */}
      <div className="upload-card">
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 'var(--space-md)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <UploadCloud size={18} color="var(--accent)" aria-hidden="true" />
            <h2 style={{ fontSize: 15, fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
              Log Ingestion & Threat Detection
            </h2>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={handleResetSample}
              disabled={uploading || isReadOnly}
              style={{ fontSize: 11, padding: '4px 10px', opacity: isReadOnly ? 0.6 : 1 }}
              title={isReadOnly ? "Reset is disabled in public read-only mode" : "Reset active live dataset back to clean empty state (0 events, 0 alerts)"}
            >
              <RefreshCw size={12} className={uploading ? 'spin-icon' : ''} />
              Reset Live Data (Clear)
            </button>
          </div>
        </div>

        {/* Public Portfolio Read-Only Banner */}
        {isReadOnly && isLiveMode && (
          <div style={{
            marginBottom: 'var(--space-md)',
            padding: '10px 14px',
            background: 'rgba(59, 130, 246, 0.08)',
            border: '1px solid rgba(59, 130, 246, 0.3)',
            borderRadius: 'var(--radius-sm)',
            fontSize: 12,
            color: '#93c5fd',
            display: 'flex',
            gap: 10,
            alignItems: 'flex-start',
            lineHeight: 1.5,
          }}>
            <Lock size={16} style={{ flexShrink: 0, marginTop: 2, color: '#60a5fa' }} />
            <div>
              <strong style={{ color: '#fff' }}>Public Portfolio Deployment Notice:</strong> Live log uploads and dataset modifications are disabled on this shared cloud instance to guarantee visitor privacy and state isolation.
              <div style={{ marginTop: 6, display: 'flex', flexDirection: 'column', gap: 4 }}>
                <div>
                  • <strong>Explore SOC Features:</strong> Switch to <span style={{ color: '#60a5fa', fontWeight: 600 }}>DEMO MODE</span> in the top navigation to interact with pre-loaded events, detections, and investigation dossiers.
                </div>
                <div>
                  • <strong>Custom Log Ingestion:</strong> Clone the repository to run ThreatLens locally for unlimited, unconstrained log uploads and threshold tuning.
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Format Selector Tabs */}
        <div className="import-format-bar">
          <button
            type="button"
            className={`import-tab-btn ${importFormat === 'windows' ? 'active' : ''}`}
            onClick={() => setImportFormat('windows')}
          >
            <Monitor size={14} />
            Windows Security Event Log (CSV)
          </button>
          <button
            type="button"
            className={`import-tab-btn ${importFormat === 'standard' ? 'active' : ''}`}
            onClick={() => setImportFormat('standard')}
          >
            <FileSpreadsheet size={14} />
            Standard ThreatLens CSV
          </button>
        </div>

        {/* Windows Format Helper & Pill Badges */}
        {importFormat === 'windows' ? (
          <div className="win-info-banner">
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: '#93c5fd', fontSize: 12, fontWeight: 600 }}>
              <Shield size={14} color="#60a5fa" />
              Windows Event Viewer CSV Importer (Phase 5)
            </div>
            <p style={{ fontSize: 11, color: 'var(--text-muted)', margin: '4px 0 8px 0' }}>
              Export from Windows Event Viewer (<strong>Security</strong> → <em>Save All Events As…</em> → CSV).
              Automatically normalizes Event IDs, timestamps, usernames, and source IPs into the SOC schema.
            </p>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em', fontWeight: 600 }}>
              Supported Windows Event IDs (10):
            </div>
            <div className="win-event-pills">
              {SUPPORTED_WINDOWS_EVENTS.map((we) => (
                <span key={we.id} className="win-event-pill" title={`${we.name} → ${we.type}`}>
                  <strong>{we.id}</strong> {we.name}
                </span>
              ))}
            </div>
          </div>
        ) : (
          <p style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 'var(--space-md)' }}>
            Upload standard security log CSV with columns: <code>timestamp</code>, <code>source_ip</code>, <code>event_type</code>, <code>username</code>, <code>status</code>.
          </p>
        )}

        {/* Upload Dropzone */}
        <div
          className={`upload-dropzone ${dragActive ? 'drag-active' : ''}`}
          onDragEnter={handleDrag}
          onDragOver={handleDrag}
          onDragLeave={handleDrag}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => { if (e.key === 'Enter') fileInputRef.current?.click(); }}
        >
          <input
            ref={fileInputRef}
            type="file"
            accept=".csv"
            style={{ display: 'none' }}
            onChange={onFileChange}
          />
          <FileText size={32} color={selectedFile ? 'var(--accent)' : 'var(--text-muted)'} />
          {selectedFile ? (
            <div>
              <div style={{ color: 'var(--text-primary)', fontWeight: 600, fontSize: 13 }}>
                Selected: {selectedFile.name}
              </div>
              <div style={{ color: 'var(--text-muted)', fontSize: 11 }}>
                {selectedFile.size >= 1024 * 1024
                  ? `${(selectedFile.size / (1024 * 1024)).toFixed(2)} MB`
                  : `${(selectedFile.size / 1024).toFixed(1)} KB`
                } • Mode: {importFormat === 'windows' ? 'Windows Event Viewer CSV' : 'Standard ThreatLens CSV'}
              </div>
            </div>
          ) : (
            <div>
              <div style={{ color: 'var(--text-primary)', fontSize: 13, fontWeight: 500 }}>
                Drop your {importFormat === 'windows' ? 'Windows Event Viewer CSV' : 'CSV log file'} here, or <span style={{ color: 'var(--accent)', textDecoration: 'underline' }}>browse</span>
              </div>
              <div style={{ color: 'var(--text-muted)', fontSize: 11, marginTop: 4 }}>
                Accepted format: .csv (maximum size: {Math.round((maxUploadBytes / (1024 * 1024)) * 10) / 10} MB)
              </div>
            </div>
          )}
        </div>

        {/* Privacy & In-Memory Confidentiality Notice */}
        <div style={{
          marginTop: 10,
          padding: '8px 12px',
          background: 'rgba(15, 23, 42, 0.6)',
          borderLeft: '3px solid var(--accent)',
          borderRadius: '0 var(--radius-sm) var(--radius-sm) 0',
          fontSize: 11,
          color: 'var(--text-muted)',
          lineHeight: 1.5,
          display: 'flex',
          gap: 8,
          alignItems: 'flex-start',
        }}>
          <Info size={14} style={{ flexShrink: 0, marginTop: 2, color: 'var(--accent)' }} />
          <span>
            <strong>In-Memory Privacy Guarantee:</strong> Uploaded CSV files are analyzed exclusively in temporary server RAM. Records are never saved to disk, stored in a database, or shared. Resetting the session or restarting the service immediately purges all active records.
          </span>
        </div>

        {/* Action button & loading state */}
        <div style={{ marginTop: 'var(--space-md)', display: 'flex', alignItems: 'center', gap: 'var(--space-md)' }}>
          <button
            type="button"
            className="btn btn-primary"
            onClick={triggerUpload}
            disabled={!selectedFile || uploading || isReadOnly}
            title={isReadOnly ? "Live upload is disabled in public read-only mode" : undefined}
          >
            {isReadOnly ? (
              <>
                <Lock size={14} />
                Uploads Disabled in Public Demo
              </>
            ) : uploading ? (
              <>
                <RefreshCw size={14} className="spin-icon" />
                Analyzing Logs with Python Engine…
              </>
            ) : (
              <>
                <UploadCloud size={14} />
                Upload & Detect Threats
              </>
            )}
          </button>

          {selectedFile && !uploading && (
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => {
                setSelectedFile(null);
                if (fileInputRef.current) fileInputRef.current.value = '';
              }}
            >
              Cancel
            </button>
          )}
        </div>

        {/* Client or Server Error Alert */}
        {(uploadError || localClientError) && (
          <div
            style={{
              marginTop: 'var(--space-md)',
              background: 'rgba(239, 68, 68, 0.12)',
              border: '1px solid rgba(239, 68, 68, 0.3)',
              borderRadius: 'var(--radius-sm)',
              padding: '10px 14px',
              display: 'flex',
              alignItems: 'flex-start',
              gap: 10,
              color: '#f87171',
            }}
            role="alert"
          >
            <AlertTriangle size={18} style={{ flexShrink: 0, marginTop: 1 }} />
            <div style={{ flex: 1, fontSize: 12 }}>
              <strong>Upload Failed: </strong>
              {uploadError || localClientError}
            </div>
            <button
              type="button"
              onClick={() => {
                clearUploadError();
                setLocalClientError(null);
              }}
              style={{ background: 'none', border: 'none', color: '#f87171', cursor: 'pointer', padding: 0 }}
              title="Dismiss error"
            >
              <X size={14} />
            </button>
          </div>
        )}

        {/* Analysis Results Summary */}
        {uploadResult && (
          <div
            style={{
              marginTop: 'var(--space-md)',
              background: 'rgba(34, 197, 94, 0.08)',
              border: '1px solid rgba(34, 197, 94, 0.25)',
              borderRadius: 'var(--radius-sm)',
              padding: '14px 16px',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: '#4ade80', fontWeight: 600, fontSize: 13 }}>
                <CheckCircle2 size={16} />
                Detection Complete for {uploadResult.filename}
              </div>
              <button
                type="button"
                onClick={clearUploadResult}
                style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', padding: 0 }}
                title="Dismiss result banner"
              >
                <X size={14} />
              </button>
            </div>

            <p style={{ fontSize: 12, color: 'var(--text-secondary)', margin: '0 0 10px 0' }}>
              Normalized <strong>{uploadResult.rowsProcessed}</strong> rows • Found{' '}
              <strong style={{ color: uploadResult.alertsDetected > 0 ? '#f87171' : '#4ade80' }}>
                {uploadResult.alertsDetected}
              </strong> threat alert(s) at {uploadResult.timestamp}.
            </p>

            {/* Windows Import Report Stats */}
            {uploadResult.importReport && (
              <div style={{ marginTop: 10, marginBottom: 12 }}>
                <div style={{ fontSize: 11, fontWeight: 600, color: '#93c5fd', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                  Windows Event Viewer Import Report:
                </div>
                <div className="import-report-grid">
                  <div className="import-report-stat">
                    <div className="import-report-stat-label">Total in Export</div>
                    <div className="import-report-stat-val">{uploadResult.importReport.total_rows}</div>
                  </div>
                  <div className="import-report-stat">
                    <div className="import-report-stat-label">Normalized</div>
                    <div className="import-report-stat-val" style={{ color: '#4ade80' }}>
                      {uploadResult.importReport.imported_rows}
                    </div>
                  </div>
                  <div className="import-report-stat">
                    <div className="import-report-stat-label">Skipped (Noise)</div>
                    <div className="import-report-stat-val" style={{ color: '#fbbf24' }}>
                      {uploadResult.importReport.skipped_rows}
                    </div>
                  </div>
                  <div className="import-report-stat">
                    <div className="import-report-stat-label">Rejected</div>
                    <div className="import-report-stat-val" style={{ color: uploadResult.importReport.rejected_rows > 0 ? '#f87171' : 'var(--text-muted)' }}>
                      {uploadResult.importReport.rejected_rows}
                    </div>
                  </div>
                </div>

                {uploadResult.importReport.unsupported_event_ids?.length > 0 && (
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
                    Skipped unsupported Event IDs:{' '}
                    {uploadResult.importReport.unsupported_event_ids.map((id) => (
                      <span key={id} style={{ display: 'inline-block', padding: '1px 5px', background: 'rgba(255,255,255,0.06)', borderRadius: 3, margin: '0 3px', fontFamily: 'var(--font-mono)' }}>
                        Event {id}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* List resulting alerts if any were detected */}
            {uploadResult.alertsDetected > 0 && alerts.length > 0 && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 8 }}>
                <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  Identified Threats ({alerts.length}):
                </div>
                {alerts.map((al) => (
                  <div key={al.id} className="upload-alert-card">
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--accent)' }}>
                          {al.id}
                        </span>
                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-primary)' }}>
                          {al.sourceIP || al.source_ip}
                        </span>
                        <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                          [{al.eventType || al.event_type}]
                        </span>
                        {al.rules_matched && (
                          <span style={{ fontSize: 10, color: '#93c5fd', background: 'rgba(59, 130, 246, 0.15)', padding: '1px 5px', borderRadius: 3 }}>
                            {al.rules_matched.join(', ')}
                          </span>
                        )}
                      </div>
                      <SeverityBadge severity={al.severity} />
                    </div>
                    <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 4 }}>
                      {al.details || al.explanation}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      {/* ── System Log Viewer Panel ──────────────────────────────────── */}
      <div className="panel">
        <div className="panel-title" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <Terminal size={15} aria-hidden="true" />
            {isUsingBackend
              ? `Parsed Log Entries (${metadata?.datasetName || 'Active Log'})`
              : 'System Log Viewer (Simulated Demo)'}
          </div>
          <span style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 400 }}>
            Showing {filteredLogs.length} of {logs.length} entries
          </span>
        </div>

        {/* Controls */}
        <div className="controls-bar">
          <div className="search-wrapper">
            <Search size={14} className="search-icon" aria-hidden="true" />
            <input
              id="logs-search"
              type="search"
              className="search-input"
              placeholder="Search by IP, Event ID (e.g. 4624), user, or message…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              aria-label="Search log entries"
            />
          </div>
          <select
            id="logs-level-filter"
            className="filter-select"
            value={level}
            onChange={(e) => setLevel(e.target.value)}
            aria-label="Filter by log level"
          >
            <option value="All">All Levels</option>
            <option value="CRITICAL">Critical</option>
            <option value="ERROR">Error</option>
            <option value="WARN">Warning</option>
            <option value="INFO">Info</option>
          </select>
        </div>

        {isLiveMode && !hasRealData ? (
          <div className="empty-state" style={{ padding: 'var(--space-xl)', textAlign: 'center' }}>
            <Terminal size={40} style={{ color: 'var(--text-muted)', marginBottom: 8 }} aria-hidden="true" />
            <div className="empty-state-title">Upload a supported CSV file to begin analysis.</div>
            <div className="empty-state-sub">
              Upload a Windows Security Event CSV or a supported ThreatLens CSV using the panel above to populate log entries.
            </div>
          </div>
        ) : filteredLogs.length === 0 ? (
          <div className="empty-state">
            <Filter size={32} aria-hidden="true" />
            <div className="empty-state-title">No log entries match your filters</div>
            <div className="empty-state-sub">Try adjusting the search query or level filter.</div>
          </div>
        ) : (
          <div
            className="log-list"
            role="log"
            aria-live="polite"
            aria-label="Log entries"
            style={{
              background: 'var(--bg-base)',
              borderRadius: 'var(--radius-md)',
              padding: 'var(--space-md)',
              border: '1px solid var(--border)',
              maxHeight: 520,
              overflowY: 'auto',
            }}
          >
            {filteredLogs.map((entry) => {
              const isExpanded = expandedLogIds.has(entry.id);
              const hasDescription = Boolean(entry.win_description);

              return (
                <div
                  key={entry.id}
                  className="log-entry"
                  style={{ display: 'block', padding: '6px 8px', borderBottom: '1px solid rgba(255,255,255,0.03)' }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                    <span className="log-time">{entry.timestamp}</span>
                    <span className={`log-level ${LEVEL_CLASS[entry.level] ?? ''}`}>
                      [{entry.level}]
                    </span>
                    {entry.win_event_id && (
                      <span className="win-badge" title={entry.win_label || 'Windows Event'}>
                        Event {entry.win_event_id}
                      </span>
                    )}
                    <span className="log-source">{entry.source}</span>
                    {entry.win_computer && (
                      <span className="win-computer-tag">
                        {entry.win_computer}
                      </span>
                    )}
                    <span className="log-msg" style={{ flex: 1 }}>{entry.message}</span>
                    {hasDescription && (
                      <button
                        type="button"
                        onClick={() => toggleExpand(entry.id)}
                        style={{
                          background: 'none',
                          border: 'none',
                          color: '#60a5fa',
                          cursor: 'pointer',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: 3,
                          fontSize: 10,
                          padding: '2px 5px',
                        }}
                        title="Toggle event details"
                      >
                        {isExpanded ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
                        {isExpanded ? 'Hide Details' : 'Details'}
                      </button>
                    )}
                  </div>
                  {isExpanded && entry.win_description && (
                    <div className="log-entry-expanded">
                      {entry.win_description}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
