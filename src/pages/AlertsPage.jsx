/**
 * AlertsPage – Phase 6
 * =====================
 * Full alert investigation and prioritization view with:
 *  - Explainable Risk-Priority Score (0–100) and Priority Badges (Critical, High, Medium, Low)
 *  - Detection Rules matched chips and Affected Account attribution
 *  - First Seen / Last Seen timeline bounds and Related Events count
 *  - Recommended Investigation Steps tailored to detection rules
 *  - Known limitations and non-speculative explanation guidance
 *  - Multi-dimension filter bar: Priority, Severity, Detection Rule, Affected Account, Source IP, Status, and Free-text search
 *  - Safe CSV export with formula-injection sanitization
 *
 * Integrated with the FastAPI detection engine via ThreatLensContext.
 */

import { useState, useMemo, Fragment } from 'react';
import {
  Search, Filter, ChevronDown, ChevronUp, Info, Server,
  Download, X, ShieldAlert, CheckCircle2, UploadCloud, WifiOff,
} from 'lucide-react';
import { useThreatLens } from '../context/ThreatLensContext';
import { DEMO_NOTICE } from '../data/demoData';
import { SeverityBadge, StatusBadge, PriorityBadge, RiskScoreBadge } from '../components/Badges';

// ── CSV export helpers ────────────────────────────────────────────────────────

function csvEscape(value) {
  if (value === null || value === undefined) return '""';
  let str = String(value);
  // Formula injection protection: strip leading dangerous characters
  str = str.replace(/^[=+\-@\t\r]+/, '');
  // Escape existing double-quotes by doubling them, then wrap in quotes
  return `"${str.replace(/"/g, '""')}"`;
}

function buildCsvRows(alerts) {
  const headers = [
    'Alert ID', 'Timestamp', 'First Seen', 'Last Seen',
    'Priority', 'Risk Score', 'Severity', 'Event Type',
    'Source IP', 'Affected Account', 'Detection Rules',
    'Status', 'Evidence Count', 'Explanation', 'Investigation Steps',
  ];

  const rows = alerts.map((a) => {
    const sourceIp   = a.sourceIP || a.source_ip || 'Not available';
    const account    = a.affected_account || 'Not available';
    const eventType  = a.eventType || a.event_type || 'Not available';
    const details    = a.details || a.explanation || '';
    const rules      = Array.isArray(a.rules_matched) ? a.rules_matched.join('; ') : '';
    const evidenceCt = Array.isArray(a.evidence) ? a.evidence.length : 0;
    const steps      = Array.isArray(a.investigation_steps) ? a.investigation_steps.join(' | ') : '';
    const priority   = a.priority_label || a.severity || 'Low';
    const riskScore  = typeof a.risk_score === 'number' ? a.risk_score : '';

    return [
      csvEscape(a.id),
      csvEscape(a.timestamp || 'Not available'),
      csvEscape(a.first_seen || a.timestamp || 'Not available'),
      csvEscape(a.last_seen || a.timestamp || 'Not available'),
      csvEscape(priority),
      csvEscape(riskScore),
      csvEscape(a.severity),
      csvEscape(eventType),
      csvEscape(sourceIp),
      csvEscape(account),
      csvEscape(rules),
      csvEscape(a.status || 'Open'),
      csvEscape(evidenceCt),
      csvEscape(details),
      csvEscape(steps),
    ].join(',');
  });

  return [headers.map(csvEscape).join(','), ...rows].join('\r\n');
}

function downloadCsv(csvString, filename) {
  const blob = new Blob([csvString], { type: 'text/csv;charset=utf-8;' });
  const url  = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.setAttribute('download', filename);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

function todayIso() {
  return new Date().toISOString().slice(0, 10);
}

// ── Filter helpers ────────────────────────────────────────────────────────────

function deriveRules(alerts) {
  const set = new Set();
  alerts.forEach((a) => {
    if (Array.isArray(a.rules_matched)) {
      a.rules_matched.forEach((r) => set.add(r));
    }
  });
  return ['All', ...Array.from(set).sort()];
}

function deriveAccounts(alerts) {
  const set = new Set();
  alerts.forEach((a) => {
    if (a.affected_account && a.affected_account !== 'Multiple' && a.affected_account !== 'Unknown') {
      set.add(a.affected_account);
    }
  });
  return ['All', ...Array.from(set).sort()];
}

function deriveSourceIps(alerts) {
  const ips = new Set(alerts.map((a) => a.sourceIP || a.source_ip).filter(Boolean));
  return ['All', ...Array.from(ips).sort()];
}

// ── Alert detail field ────────────────────────────────────────────────────────

function DetailField({ label, value, mono = false, className = '' }) {
  const display = value !== null && value !== undefined && value !== '' ? value : 'Not available';
  return (
    <div className={className} style={{ marginBottom: 8, minWidth: 0 }}>
      <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
        {label}
      </span>
      <div
        style={{
          fontSize: 12,
          color: 'var(--text-secondary)',
          fontFamily: mono ? 'var(--font-mono)' : undefined,
          marginTop: 2,
          whiteSpace: 'normal',
          wordBreak: 'break-word',
          overflowWrap: 'anywhere',
        }}
      >
        {display}
      </div>
    </div>
  );
}

// ── Alert Investigation Panel ─────────────────────────────────────────────────

function AlertInvestigationPanel({ alert }) {
  const sourceIp    = alert.sourceIP || alert.source_ip;
  const details     = alert.details || alert.explanation;
  const rules       = Array.isArray(alert.rules_matched) ? alert.rules_matched : [];
  const evidence    = Array.isArray(alert.evidence) ? alert.evidence : [];
  const steps       = Array.isArray(alert.investigation_steps) ? alert.investigation_steps : [];
  const factors     = Array.isArray(alert.score_factors) ? alert.score_factors : [];
  const priority    = alert.priority_label || alert.severity || 'Low';
  const riskScore   = typeof alert.risk_score === 'number' ? Math.round(alert.risk_score) : null;
  const account     = alert.affected_account || 'Not identified';

  const triggerCount = alert.triggering_count ?? evidence.filter((e) => e.evidence_role !== 'correlated_context').length;
  const contextCount = alert.context_count ?? evidence.filter((e) => e.evidence_role === 'correlated_context').length;
  const evidenceEventsDisplay = contextCount > 0
    ? `${triggerCount} triggering, ${contextCount} correlated context (${evidence.length} total)`
    : `${evidence.length} related event(s)`;

  return (
    <div className="alert-investigation-panel">
      {/* Header bar */}
      <div className="aip-header" style={{ flexWrap: 'wrap', gap: 10 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <ShieldAlert size={16} color="var(--accent)" aria-hidden="true" />
          <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>
            Investigation Dossier: {alert.id}
          </span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          {riskScore !== null && <RiskScoreBadge score={riskScore} priority={priority} />}
          <PriorityBadge priority={priority} />
          <SeverityBadge severity={alert.severity} />
        </div>
      </div>

      {/* Responsive grid for key investigation attributes */}
      <div className="aip-fields-grid">
        <DetailField label="Alert ID"          value={alert.id} mono />
        <DetailField className="aip-field-timeline" label="Observed Timeline" value={`${alert.first_seen || alert.timestamp || 'n/a'} → ${alert.last_seen || alert.timestamp || 'n/a'}`} mono />
        <DetailField label="Source IP"         value={sourceIp} mono />
        <DetailField label="Affected Account"  value={account} mono />
        <DetailField label="Status"            value={alert.status || 'Open'} />
        <DetailField label="Evidence Events"   value={evidenceEventsDisplay} />
      </div>

      {/* Detection rules matched */}
      {rules.length > 0 && (
        <div style={{ marginBottom: 14 }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: 6 }}>
            Detection Rules Triggered
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {rules.map((r) => (
              <span key={r} className="rule-chip" style={{ fontSize: 11 }}>{r}</span>
            ))}
          </div>
        </div>
      )}

      {/* Risk Scoring Breakdown */}
      {factors.length > 0 && (
        <div style={{ marginBottom: 14 }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: 6 }}>
            Risk Score Breakdown ({riskScore !== null ? `${riskScore}/100` : 'Deterministic Formula'})
          </div>
          <div className="score-factors-wrap">
            {factors.map((f, i) => (
              <span key={i} className="factor-chip">
                {typeof f === 'string' ? f : `${f.factor}: +${f.points} pts`}
              </span>
            ))}
          </div>
          <p style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 4, fontStyle: 'italic' }}>
            Score is computed deterministically from rule severity baseline, event frequency, multi-rule correlation, and privilege indicators. It is not an attack probability.
          </p>
        </div>
      )}

      {/* Why this was flagged (Explanation) */}
      {details && (
        <div style={{ marginBottom: 14 }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: 4 }}>
            Detection Context & Why It Was Flagged
          </div>
          <div style={{
            fontSize: 12,
            color: 'var(--text-secondary)',
            lineHeight: 1.6,
            padding: '10px 12px',
            background: 'rgba(59,130,246,0.06)',
            borderLeft: '3px solid var(--accent)',
            borderRadius: '0 4px 4px 0',
            whiteSpace: 'normal',
            wordBreak: 'break-word',
            overflowWrap: 'break-word',
          }}>
            {details}
          </div>
        </div>
      )}

      {/* Recommended Investigation Steps */}
      {steps.length > 0 && (
        <div className="investigation-steps-box">
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 8 }}>
            <CheckCircle2 size={14} color="#3b82f6" />
            <span>Recommended SOC Investigation Steps</span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {steps.map((st, i) => (
              <div key={i} className="step-item">
                <span className="step-num">{i + 1}</span>
                <span>{st}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Limitations note */}
      {alert.limitations && (
        <div className="limitations-box">
          <strong>Investigation Limitations: </strong>
          {alert.limitations}
        </div>
      )}

      {/* Attribution guardrail note */}
      <div style={{ marginBottom: 14, fontSize: 11, color: 'var(--text-muted)', fontStyle: 'italic', display: 'flex', gap: 6, alignItems: 'flex-start' }}>
        <Info size={13} style={{ flexShrink: 0, marginTop: 2, color: 'var(--accent)' }} />
        <span>
          <strong>SOC Guardrail:</strong> Alerts indicate detected pattern anomalies from log records; they do not automatically confirm external intrusion, malicious intent, or system compromise without corroborating host/network evidence.
        </span>
      </div>

      {/* Evidence table */}
      {evidence.length > 0 && (
        <div>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em', marginBottom: 6 }}>
            Supporting Evidence ({evidence.length} log event{evidence.length !== 1 ? 's' : ''})
          </div>

          {contextCount > 0 && (
            <div className="correlated-context-banner">
              <Info size={13} style={{ flexShrink: 0, marginTop: 1, color: '#38bdf8' }} />
              <span>
                <strong>Correlated Contextual Evidence:</strong> This alert includes {contextCount} subsequent event(s) (such as successful authentication) correlated by the detection engine. Contextual events provide forensic visibility into the incident timeline and do not increment brute-force failure counts.
              </span>
            </div>
          )}

          <div className="evidence-table-wrap">
            <table className="evidence-table" aria-label={`Evidence for ${alert.id}`}>
              <thead>
                <tr>
                  <th>#</th>
                  <th>Evidence Role</th>
                  <th>Timestamp</th>
                  <th>Source IP</th>
                  <th>Event Type / Win ID</th>
                  <th>User / Target</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {evidence.slice(0, 25).map((ev, i) => {
                  const isContext = ev.evidence_role === 'correlated_context';
                  return (
                    <tr key={i} style={isContext ? { background: 'rgba(14, 165, 233, 0.04)' } : undefined}>
                      <td style={{ color: 'var(--text-muted)' }}>{i + 1}</td>
                      <td>
                        <span className={`evidence-role-badge ${isContext ? 'context' : 'triggering'}`}>
                          {isContext ? 'Correlated Context' : 'Triggering Event'}
                        </span>
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)' }}>{ev.timestamp ?? 'n/a'}</td>
                      <td style={{ fontFamily: 'var(--font-mono)' }}>{ev.source_ip ?? 'n/a'}</td>
                      <td>
                        {ev.win_event_id && (
                          <span className="win-badge" style={{ fontSize: 10, padding: '0 4px', marginRight: 4 }}>
                            Event {ev.win_event_id}
                          </span>
                        )}
                        {ev.event_type ?? 'n/a'}
                      </td>
                      <td>{ev.username ?? 'n/a'}</td>
                      <td>{ev.status ?? 'n/a'}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            {evidence.length > 25 && (
              <div style={{ fontSize: 11, color: 'var(--text-muted)', padding: '6px 10px', fontStyle: 'italic' }}>
                … and {evidence.length - 25} more evidence event(s) not shown.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Main Alerts Page ──────────────────────────────────────────────────────────

export default function AlertsPage() {
  const { alerts, isLiveMode, hasRealData, backendStatus, metadata } = useThreatLens();

  const [search,    setSearch]    = useState('');
  const [priority,  setPriority]  = useState('All');
  const [severity,  setSeverity]  = useState('All');
  const [rule,      setRule]      = useState('All');
  const [account,   setAccount]   = useState('All');
  const [sourceIp,  setSourceIp]  = useState('All');
  const [status,    setStatus]    = useState('All');
  const [expanded,  setExpanded]  = useState(null);
  const [exportMsg, setExportMsg] = useState(null);

  // Derive filter options
  const ruleOptions    = useMemo(() => deriveRules(alerts), [alerts]);
  const accountOptions = useMemo(() => deriveAccounts(alerts), [alerts]);
  const sourceIpOptions = useMemo(() => deriveSourceIps(alerts), [alerts]);

  // Combined client-side filtering
  const filtered = useMemo(() => {
    const q = search.toLowerCase().trim();
    return alerts.filter((a) => {
      const srcIp    = (a.sourceIP || a.source_ip || '').toLowerCase();
      const acct     = (a.affected_account || '').toLowerCase();
      const evType   = (a.eventType || a.event_type || '').toLowerCase();
      const details  = (a.details || a.explanation || '').toLowerCase();
      const rulesArr = Array.isArray(a.rules_matched) ? a.rules_matched : [];
      const rulesStr = rulesArr.join(' ').toLowerCase();
      const prio     = a.priority_label || a.severity || 'Low';
      const alertSt  = a.status || 'Open';

      const matchSearch =
        !q ||
        (a.id || '').toLowerCase().includes(q) ||
        srcIp.includes(q) ||
        acct.includes(q) ||
        evType.includes(q) ||
        details.includes(q) ||
        rulesStr.includes(q);

      const matchPriority = priority === 'All' || prio.toLowerCase() === priority.toLowerCase();
      const matchSeverity = severity === 'All' || a.severity === severity;
      const matchRule     = rule === 'All' || rulesArr.includes(rule);
      const matchAccount  = account === 'All' || a.affected_account === account;
      const matchSrcIp    = sourceIp === 'All' || (a.sourceIP || a.source_ip) === sourceIp;
      const matchStatus   = status === 'All' || alertSt === status;

      return matchSearch && matchPriority && matchSeverity && matchRule && matchAccount && matchSrcIp && matchStatus;
    });
  }, [alerts, search, priority, severity, rule, account, sourceIp, status]);

  const hasActiveFilters =
    search !== '' ||
    priority !== 'All' ||
    severity !== 'All' ||
    rule !== 'All' ||
    account !== 'All' ||
    sourceIp !== 'All' ||
    status !== 'All';

  const resetFilters = () => {
    setSearch('');
    setPriority('All');
    setSeverity('All');
    setRule('All');
    setAccount('All');
    setSourceIp('All');
    setStatus('All');
  };

  const toggle = (id) => setExpanded((prev) => (prev === id ? null : id));

  // CSV export handler
  const handleExport = () => {
    if (filtered.length === 0) {
      setExportMsg('No alerts to export. Adjust your filters first.');
      setTimeout(() => setExportMsg(null), 3500);
      return;
    }
    const csv      = buildCsvRows(filtered);
    const filename = `threatlens-prioritized-alerts-${todayIso()}.csv`;
    downloadCsv(csv, filename);
    setExportMsg(`Exported ${filtered.length} prioritized alert(s) to ${filename}.`);
    setTimeout(() => setExportMsg(null), 3500);
  };

  return (
    <div className="page-content">
      {/* Dynamic notice bar — mode-aware */}
      {isLiveMode ? (
        hasRealData ? (
          <div
            className="demo-notice-bar"
            role="note"
            style={{ background: 'rgba(34,197,94,0.08)', border: '1px solid rgba(34,197,94,0.2)', color: '#4ade80' }}
          >
            <Server size={16} style={{ flexShrink: 0, marginTop: 2 }} aria-hidden="true" />
            <span>
              <strong>Prioritized Alerts:</strong> Categorized with explainable 0–100 risk scoring from{' '}
              <code>{metadata?.datasetName || 'uploaded file'}</code>. Click any row to view score factors and investigation steps.
            </span>
          </div>
        ) : backendStatus === 'disconnected' ? (
          <div
            className="demo-notice-bar"
            role="alert"
            style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)', color: '#f87171' }}
          >
            <WifiOff size={16} style={{ flexShrink: 0, marginTop: 2 }} aria-hidden="true" />
            <span><strong>Backend Offline:</strong> Cannot connect to the FastAPI backend. Start the backend server and retry.</span>
          </div>
        ) : (
          <div
            className="demo-notice-bar"
            role="note"
            style={{ background: 'rgba(234,179,8,0.06)', border: '1px solid rgba(234,179,8,0.2)', color: '#fbbf24' }}
          >
            <UploadCloud size={16} style={{ flexShrink: 0, marginTop: 2 }} aria-hidden="true" />
            <span><strong>Live Mode — No Data:</strong> No alerts detected. Upload and analyze security logs via Log Analysis to view alerts.</span>
          </div>
        )
      ) : (
        <div className="demo-notice-bar" role="note">
          <Info size={16} style={{ flexShrink: 0, marginTop: 2 }} aria-hidden="true" />
          <span>{DEMO_NOTICE} (Showing static demo alerts — switch to Live Mode to analyze real logs).</span>
        </div>
      )}

      {/* ── Live mode empty state ───────────────────────────────────────── */}
      {isLiveMode && !hasRealData ? (
        <div className="empty-state" style={{ padding: 'var(--space-xl)', textAlign: 'center' }}>
          <ShieldAlert size={48} style={{ color: 'var(--text-muted)', marginBottom: 12 }} aria-hidden="true" />
          <div className="empty-state-title">No Alerts Detected</div>
          <div className="empty-state-sub">
            Upload and analyze security logs via <strong>Log Analysis</strong> to view alerts.
          </div>
        </div>
      ) : (

      <div className="panel">
        {/* ── Multi-filter bar ────────────────────────────────────────── */}
        <div className="controls-bar" style={{ flexWrap: 'wrap', gap: 8 }}>
          {/* Free-text search */}
          <div className="search-wrapper" style={{ flex: '1 1 200px' }}>
            <Search size={14} className="search-icon" aria-hidden="true" />
            <input
              id="alerts-search"
              type="search"
              className="search-input"
              placeholder="Search by IP, account, rule, ID…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              aria-label="Search alerts"
            />
          </div>

          {/* Priority Filter */}
          <select
            id="alerts-priority-filter"
            className="filter-select"
            value={priority}
            onChange={(e) => setPriority(e.target.value)}
            aria-label="Filter by priority label"
          >
            <option value="All">All Priorities</option>
            <option value="Critical">Critical Priority</option>
            <option value="High">High Priority</option>
            <option value="Medium">Medium Priority</option>
            <option value="Low">Low Priority</option>
          </select>

          {/* Severity Filter */}
          <select
            id="alerts-severity-filter"
            className="filter-select"
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
            aria-label="Filter by severity"
          >
            <option value="All">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>

          {/* Detection Rule Filter */}
          <select
            id="alerts-rule-filter"
            className="filter-select"
            value={rule}
            onChange={(e) => setRule(e.target.value)}
            aria-label="Filter by detection rule"
          >
            {ruleOptions.map((r) => (
              <option key={r} value={r}>{r === 'All' ? 'All Detection Rules' : r}</option>
            ))}
          </select>

          {/* Affected Account Filter */}
          <select
            id="alerts-account-filter"
            className="filter-select"
            value={account}
            onChange={(e) => setAccount(e.target.value)}
            aria-label="Filter by affected account"
          >
            {accountOptions.map((ac) => (
              <option key={ac} value={ac}>{ac === 'All' ? 'All Accounts' : ac}</option>
            ))}
          </select>

          {/* Source IP Filter */}
          <select
            id="alerts-sourceip-filter"
            className="filter-select"
            value={sourceIp}
            onChange={(e) => setSourceIp(e.target.value)}
            aria-label="Filter by source IP"
          >
            {sourceIpOptions.map((ip) => (
              <option key={ip} value={ip}>{ip === 'All' ? 'All Source IPs' : ip}</option>
            ))}
          </select>

          {/* Status Filter */}
          <select
            id="alerts-status-filter"
            className="filter-select"
            value={status}
            onChange={(e) => setStatus(e.target.value)}
            aria-label="Filter by status"
          >
            <option value="All">All Statuses</option>
            <option value="Open">Open</option>
            <option value="Investigating">Investigating</option>
            <option value="Resolved">Resolved</option>
            <option value="False Positive">False Positive</option>
          </select>
        </div>

        {/* ── Count row + CSV export ──────────────────────────────────── */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 'var(--space-md)', gap: 8, flexWrap: 'wrap' }}>
          <p style={{ fontSize: 12, color: 'var(--text-muted)', margin: 0 }}>
            Showing <strong style={{ color: 'var(--text-primary)' }}>{filtered.length}</strong> of{' '}
            <strong style={{ color: 'var(--text-primary)' }}>{alerts.length}</strong> alerts
            {hasActiveFilters && (
              <button
                type="button"
                onClick={resetFilters}
                style={{ marginLeft: 10, background: 'none', border: 'none', color: 'var(--accent)', cursor: 'pointer', fontSize: 11, padding: 0, textDecoration: 'underline' }}
                aria-label="Clear all filters"
              >
                Clear all filters
              </button>
            )}
          </p>

          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <button
              id="alerts-export-btn"
              type="button"
              className="btn btn-secondary"
              onClick={handleExport}
              style={{ fontSize: 11, padding: '5px 12px' }}
              title={filtered.length === 0 ? 'No alerts to export' : `Export ${filtered.length} alert(s) to CSV`}
            >
              <Download size={12} />
              Export CSV
            </button>
          </div>
        </div>

        {/* Feedback message */}
        {exportMsg && (
          <div
            role="status"
            aria-live="polite"
            style={{
              marginBottom: 'var(--space-md)',
              background: filtered.length === 0 ? 'rgba(239,68,68,0.1)' : 'rgba(34,197,94,0.08)',
              border: `1px solid ${filtered.length === 0 ? 'rgba(239,68,68,0.3)' : 'rgba(34,197,94,0.25)'}`,
              borderRadius: 'var(--radius-sm)',
              padding: '8px 14px',
              fontSize: 12,
              color: filtered.length === 0 ? '#f87171' : '#4ade80',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
            }}
          >
            {exportMsg}
            <button type="button" onClick={() => setExportMsg(null)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'inherit', padding: 0 }}>
              <X size={12} />
            </button>
          </div>
        )}

        {/* ── Alerts table ─────────────────────────────────────────────── */}
        {filtered.length === 0 ? (
          <div className="empty-state">
            <Filter size={32} aria-hidden="true" />
            <div className="empty-state-title">No alerts match your active filters</div>
            <div className="empty-state-sub">
              Adjust your search keywords or filter dropdowns above.
              {hasActiveFilters && (
                <button
                  type="button"
                  onClick={resetFilters}
                  style={{ marginLeft: 8, background: 'none', border: 'none', color: 'var(--accent)', cursor: 'pointer', fontSize: 12, textDecoration: 'underline', padding: 0 }}
                >
                  Clear all filters
                </button>
              )}
            </div>
          </div>
        ) : (
          <div className="alerts-table-wrap">
            <table className="alerts-table" aria-label="Security alerts">
              <thead>
                <tr>
                  <th scope="col" style={{ width: 32 }} />
                  <th scope="col">Alert ID</th>
                  <th scope="col">Priority</th>
                  <th scope="col">Risk Score</th>
                  <th scope="col">Severity</th>
                  <th scope="col">Rules Matched</th>
                  <th scope="col">Source IP</th>
                  <th scope="col">Affected Account</th>
                  <th scope="col">Last Seen</th>
                  <th scope="col">Status</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((alert) => {
                  const isExp    = expanded === alert.id;
                  const sourceIp = alert.sourceIP || alert.source_ip || 'n/a';
                  const account  = alert.affected_account || 'n/a';
                  const rules    = Array.isArray(alert.rules_matched) ? alert.rules_matched : [];
                  const priority = alert.priority_label || alert.severity || 'Low';
                  const riskScore = typeof alert.risk_score === 'number' ? Math.round(alert.risk_score) : null;
                  const timeDisplay = alert.last_seen || alert.timestamp || 'n/a';

                  return (
                    <Fragment key={alert.id}>
                      <tr
                        className={isExp ? 'alert-row-expanded' : ''}
                        style={{ cursor: 'pointer' }}
                        onClick={() => toggle(alert.id)}
                      >
                        <td style={{ textAlign: 'center' }}>
                          <button
                            aria-expanded={isExp}
                            aria-label={`${isExp ? 'Collapse' : 'Expand'} investigation panel for ${alert.id}`}
                            style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', display: 'flex', alignItems: 'center' }}
                            onClick={(e) => { e.stopPropagation(); toggle(alert.id); }}
                          >
                            {isExp ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                          </button>
                        </td>
                        <td className="col-id">{alert.id}</td>
                        <td><PriorityBadge priority={priority} /></td>
                        <td>
                          {riskScore !== null ? (
                            <RiskScoreBadge score={riskScore} priority={priority} />
                          ) : (
                            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>n/a</span>
                          )}
                        </td>
                        <td><SeverityBadge severity={alert.severity} /></td>
                        <td>
                          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                            {rules.slice(0, 2).map((r) => (
                              <span key={r} className="rule-chip" style={{ fontSize: 10, padding: '1px 5px' }}>{r}</span>
                            ))}
                            {rules.length > 2 && (
                              <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>+{rules.length - 2}</span>
                            )}
                          </div>
                        </td>
                        <td className="col-ip">{sourceIp}</td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{account}</td>
                        <td className="col-time" style={{ fontSize: 11 }}>{timeDisplay}</td>
                        <td><StatusBadge status={alert.status || 'Open'} /></td>
                      </tr>

                      {isExp && (
                        <tr>
                          <td colSpan={10} style={{ padding: 0 }}>
                            <AlertInvestigationPanel alert={alert} />
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
      )}
    </div>
  );
}
