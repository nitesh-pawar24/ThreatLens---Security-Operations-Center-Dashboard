/**
 * Overview page – summary cards, activity chart, severity distribution,
 * top detection rules, recent alerts table with priority/risk scoring,
 * and top suspicious IPs.
 *
 * Integrated with the FastAPI detection engine via ThreatLensContext.
 */

import { useState } from 'react';
import {
  AreaChart, Area, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
} from 'recharts';
import {
  Activity, ShieldAlert, AlertTriangle, Globe,
  Search, Filter, Info, Server, RefreshCw,
  Flame, UploadCloud, WifiOff,
} from 'lucide-react';
import { useThreatLens } from '../context/ThreatLensContext';
import { DEMO_NOTICE } from '../data/demoData';
import { SeverityBadge, StatusBadge, PriorityBadge, RiskScoreBadge } from '../components/Badges';

// ── Custom tooltip for Recharts ──────────────────────────────────────────────
function CustomTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="custom-tooltip">
      <div className="custom-tooltip-label">{label}</div>
      {payload.map((p) => (
        <div key={p.dataKey} className="custom-tooltip-item">
          <span className="custom-tooltip-dot" style={{ background: p.color || p.stroke }} />
          <span>{p.name}: <strong>{(p.value ?? 0).toLocaleString()}</strong></span>
        </div>
      ))}
    </div>
  );
}

// ── Stat card ────────────────────────────────────────────────────────────────
function StatCard({ label, value, icon: Icon, iconBg, iconColor, trend }) {
  return (
    <div className="stat-card">
      <div className="stat-card-header">
        <span className="stat-card-label">{label}</span>
        <div className="stat-card-icon" style={{ background: iconBg }}>
          <Icon size={16} color={iconColor} aria-hidden="true" />
        </div>
      </div>
      <div className="stat-card-value">{(value ?? 0).toLocaleString()}</div>
      <div className="stat-card-trend">{trend}</div>
    </div>
  );
}

// ── Main component ───────────────────────────────────────────────────────────
export default function OverviewPage() {
  const {
    summaryStats,
    activityData,
    severityData,
    alerts,
    suspiciousIPs,
    topRules,
    isUsingBackend,
    isLiveMode,
    hasRealData,
    metadata,
    isLoading,
    backendStatus,
    refreshBackend,
    isReadOnly,
  } = useThreatLens();

  const [search, setSearch]     = useState('');
  const [severity, setSeverity] = useState('All');

  const filtered = alerts.filter((a) => {
    const q = search.toLowerCase();
    const source = (a.sourceIP || a.source_ip || '').toLowerCase();
    const type = (a.eventType || a.event_type || '').toLowerCase();
    const rules = Array.isArray(a.rules_matched) ? a.rules_matched.join(' ').toLowerCase() : '';
    const acct = (a.affected_account || '').toLowerCase();

    const matchesSearch =
      !q ||
      source.includes(q) ||
      type.includes(q) ||
      rules.includes(q) ||
      acct.includes(q) ||
      a.id.toLowerCase().includes(q);

    const matchesSeverity = severity === 'All' || a.severity === severity;
    return matchesSearch && matchesSeverity;
  });

  const highPriorityCount = summaryStats.highPriorityAlerts ?? (
    alerts.filter((a) => (a.priority_label || a.severity) === 'High' || (a.priority_label || a.severity) === 'Critical').length
  );

  return (
    <div className="page-content">
      {/* Dynamic notice bar — mode-aware */}
      {isLiveMode ? (
        hasRealData ? (
          <div
            className="demo-notice-bar"
            role="note"
            aria-label="Live mode — real data loaded"
            style={{ background: 'rgba(34,197,94,0.08)', border: '1px solid rgba(34,197,94,0.2)', color: '#4ade80' }}
          >
            <Server size={16} style={{ flexShrink: 0, marginTop: 2 }} aria-hidden="true" />
            <span>
              <strong>Live Mode:</strong> Displaying real analysis from{' '}
              <code style={{ background: 'rgba(0,0,0,0.3)', padding: '1px 5px', borderRadius: 3 }}>
                {metadata?.datasetName || 'uploaded file'}
              </code>
              {' '}({metadata?.rowsProcessed ?? 0} rows processed, {metadata?.alertsDetected ?? 0} alerts detected).
            </span>
          </div>
        ) : backendStatus === 'disconnected' ? (
          <div
            className="demo-notice-bar"
            role="alert"
            aria-label="Backend offline"
            style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)', color: '#f87171' }}
          >
            <WifiOff size={16} style={{ flexShrink: 0, marginTop: 2 }} aria-hidden="true" />
            <span>
              <strong>Backend Offline:</strong> Cannot connect to the FastAPI backend. Start the backend server and retry.
            </span>
          </div>
        ) : (
          <div
            className="demo-notice-bar"
            role="note"
            aria-label="Live mode — awaiting upload"
            style={{ background: 'rgba(234,179,8,0.06)', border: '1px solid rgba(234,179,8,0.2)', color: '#fbbf24' }}
          >
            <UploadCloud size={16} style={{ flexShrink: 0, marginTop: 2 }} aria-hidden="true" />
            <span>
              <strong>Live Mode — No Data:</strong>{' '}
              {isReadOnly
                ? 'Public instance is in read-only mode to preserve visitor privacy. Switch to Demo Mode above to explore all features, or clone the repository locally.'
                : 'No security logs have been analyzed yet. Upload a Windows Security Event CSV or a ThreatLens CSV via Log Analysis to begin.'}
            </span>
          </div>
        )
      ) : (
        <div className="demo-notice-bar" role="note" aria-label="Demo mode active">
          <Info size={16} style={{ flexShrink: 0, marginTop: 2 }} aria-hidden="true" />
          <span>{DEMO_NOTICE} (Showing static demo data — switch to Live Mode to analyze real logs).</span>
        </div>
      )}

      {/* ── Live mode empty state ───────────────────────────────────────── */}
      {isLiveMode && !hasRealData && (
        <div className="empty-state" style={{ padding: 'var(--space-xl)', textAlign: 'center', marginBottom: 'var(--space-xl)' }}>
          <UploadCloud size={48} style={{ color: 'var(--text-muted)', marginBottom: 12 }} aria-hidden="true" />
          <div className="empty-state-title">No Security Activity Available</div>
          <div className="empty-state-sub">
            {isReadOnly ? (
              <>
                In this public deployment, live log uploads are disabled to preserve visitor isolation and data privacy.
                Switch to <strong>Demo Mode</strong> in the top navigation to explore full SOC detection features, or run ThreatLens locally.
              </>
            ) : (
              <>
                Upload a Windows Security Event CSV or a supported ThreatLens CSV via{' '}
                <strong>Log Analysis</strong> to begin.
              </>
            )}
          </div>
        </div>
      )}

      {/* ── Summary cards ──────────────────────────────────────────────── */}
      <div className="section-heading" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <span>Summary Metrics & Threat Prioritization</span>
        {isUsingBackend && (
          <button
            type="button"
            onClick={refreshBackend}
            style={{
              background: 'transparent',
              border: 'none',
              color: 'var(--text-muted)',
              fontSize: 12,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: 4,
            }}
          >
            <RefreshCw size={12} className={isLoading ? 'spin-icon' : ''} />
            Refresh
          </button>
        )}
      </div>

      <div className="cards-grid">
        <StatCard
          label="Total Events"
          value={summaryStats.totalEvents}
          icon={Activity}
          iconBg="rgba(59,130,246,0.15)"
          iconColor="#3b82f6"
          trend={isUsingBackend ? `Rows in ${metadata?.datasetName || 'dataset'}` : 'Last 14 days · simulated'}
        />
        <StatCard
          label="Threats Detected"
          value={summaryStats.threatsDetected}
          icon={ShieldAlert}
          iconBg="rgba(249,115,22,0.15)"
          iconColor="#f97316"
          trend={isUsingBackend ? 'Consolidated security alerts' : 'Across all severity levels'}
        />
        <StatCard
          label="High Priority Threats"
          value={highPriorityCount}
          icon={Flame}
          iconBg="rgba(249,115,22,0.15)"
          iconColor="#f97316"
          trend="Score >= 60 (Requires urgent SOC review)"
        />
        <StatCard
          label="Critical Alerts"
          value={summaryStats.criticalAlerts}
          icon={AlertTriangle}
          iconBg="rgba(239,68,68,0.15)"
          iconColor="#ef4444"
          trend="Score >= 80 or Critical audit events"
        />
        <StatCard
          label="Unique IPs"
          value={summaryStats.uniqueIPs}
          icon={Globe}
          iconBg="rgba(34,197,94,0.15)"
          iconColor="#22c55e"
          trend={isUsingBackend ? 'Distinct sources parsed' : 'Active source addresses'}
        />
      </div>

      {/* ── Charts & Top Rules ─────────────────────────────────────────── */}
      <div className="section-heading">Activity & Distribution</div>
      <div className="charts-row">
        {/* Area chart – events over time */}
        <div className="panel">
          <div className="panel-title">
            <Activity size={15} aria-hidden="true" />
            {isUsingBackend ? 'Security Events & Threats Timeline' : 'Security Events Over Time (14 days)'}
          </div>
          {activityData && activityData.length > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <AreaChart data={activityData} margin={{ top: 4, right: 8, left: -10, bottom: 0 }}>
                <defs>
                  <linearGradient id="eventsGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#3b82f6" stopOpacity={0.25} />
                    <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="threatsGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#ef4444" stopOpacity={0.25} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="date" tick={{ fontSize: 11 }} />
                <YAxis tick={{ fontSize: 11 }} />
                <Tooltip content={<CustomTooltip />} />
                <Legend wrapperStyle={{ fontSize: 11 }} />
                <Area
                  type="monotone" dataKey="events" name="Events"
                  stroke="#3b82f6" fill="url(#eventsGrad)" strokeWidth={2}
                />
                <Area
                  type="monotone" dataKey="threats" name="Threats"
                  stroke="#ef4444" fill="url(#threatsGrad)" strokeWidth={2}
                />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div className="empty-state" style={{ height: 220, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <div className="empty-state-sub">No chronological activity data available for this dataset.</div>
            </div>
          )}
        </div>

        {/* Pie chart – severity distribution */}
        <div className="panel">
          <div className="panel-title">
            <ShieldAlert size={15} aria-hidden="true" />
            Alert Severity Breakdown
          </div>
          {severityData && severityData.some((entry) => entry.value > 0) ? (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie
                  data={severityData}
                  cx="50%" cy="50%"
                  innerRadius={55} outerRadius={85}
                  paddingAngle={3}
                  dataKey="value"
                  aria-label="Severity distribution chart"
                >
                  {severityData.map((entry) => (
                    <Cell key={entry.name} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  formatter={(v, n) => [v, n]}
                  contentStyle={{
                    background: 'var(--bg-panel-alt)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 8,
                    fontSize: 12,
                  }}
                />
                <Legend
                  wrapperStyle={{ fontSize: 11 }}
                  formatter={(value, entry) => (
                    <span style={{ color: entry.color }}>{value}</span>
                  )}
                />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="empty-state" style={{ height: 220, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <div className="empty-state-sub">No alert severity data available.</div>
            </div>
          )}
        </div>
      </div>

      {/* ── Top Triggered Detection Rules ──────────────────────────────── */}
      {topRules && topRules.length > 0 && (
        <>
          <div className="section-heading">Most Frequently Triggered Detection Rules</div>
          <div className="panel" style={{ marginBottom: 'var(--space-xl)' }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 12 }}>
              {topRules.map((tr) => (
                <div
                  key={tr.rule}
                  style={{
                    background: 'var(--bg-panel-alt)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-sm)',
                    padding: '12px 14px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                  }}
                >
                  <div>
                    <span className="rule-chip" style={{ fontSize: 11, fontWeight: 600 }}>{tr.rule}</span>
                  </div>
                  <div style={{ textAlign: 'right' }}>
                    <span style={{ fontSize: 16, fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>
                      {tr.count}
                    </span>
                    <span style={{ fontSize: 10, color: 'var(--text-muted)', display: 'block' }}>alert{tr.count !== 1 ? 's' : ''}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </>
      )}

      {/* ── Recent alerts ───────────────────────────────────────────────── */}
      <div className="section-heading">Recent Prioritized Alerts</div>
      <div className="panel" style={{ marginBottom: 'var(--space-xl)' }}>
        {/* Controls */}
        <div className="controls-bar">
          <div className="search-wrapper">
            <Search size={14} className="search-icon" aria-hidden="true" />
            <input
              id="overview-search"
              type="search"
              className="search-input"
              placeholder="Search by IP, account, rule, or ID…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              aria-label="Search alerts"
            />
          </div>
          <select
            id="overview-severity-filter"
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
        </div>

        {/* Table */}
        {filtered.length === 0 ? (
          <div className="empty-state">
            <Filter size={32} aria-hidden="true" />
            <div className="empty-state-title">
              {isLiveMode && !hasRealData ? 'No alerts detected' : 'No alerts match your filters'}
            </div>
            <div className="empty-state-sub">
              {isLiveMode && !hasRealData
                ? (isReadOnly
                    ? 'In this public portfolio deployment, live uploads are disabled. Switch to Demo Mode above to explore 18+ simulated events.'
                    : 'Upload and analyze security logs to view alerts.')
                : 'Try adjusting the search or severity filter.'}
            </div>
          </div>
        ) : (
          <div className="alerts-table-wrap">
            <table className="alerts-table" aria-label="Recent security alerts">
              <thead>
                <tr>
                  <th scope="col">Alert ID</th>
                  <th scope="col">Priority</th>
                  <th scope="col">Risk Score</th>
                  <th scope="col">Severity</th>
                  <th scope="col">Rules Matched</th>
                  <th scope="col">Source IP</th>
                  <th scope="col">Affected Account</th>
                  <th scope="col">Status</th>
                </tr>
              </thead>
              <tbody>
                {filtered.slice(0, 10).map((alert) => {
                  const prio = alert.priority_label || alert.severity || 'Low';
                  const riskScore = typeof alert.risk_score === 'number' ? Math.round(alert.risk_score) : null;
                  const rules = Array.isArray(alert.rules_matched) ? alert.rules_matched : [];
                  const acct = alert.affected_account || 'n/a';

                  return (
                    <tr key={alert.id}>
                      <td className="col-id">{alert.id}</td>
                      <td><PriorityBadge priority={prio} /></td>
                      <td>
                        {riskScore !== null ? (
                          <RiskScoreBadge score={riskScore} priority={prio} />
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
                        </div>
                      </td>
                      <td className="col-ip">{alert.sourceIP || alert.source_ip}</td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{acct}</td>
                      <td><StatusBadge status={alert.status || 'Open'} /></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* ── Top suspicious IPs ──────────────────────────────────────────── */}
      <div className="section-heading">Top Suspicious Addresses</div>
      <div className="panel">
        <div className="panel-title">
          <Globe size={15} aria-hidden="true" />
          {isUsingBackend ? 'Analyzed source addresses with highest activity & threat score' : 'Highest-activity addresses (simulated)'}
        </div>
        <div className="ip-list">
          {suspiciousIPs.length === 0 ? (
            <div className="empty-state" style={{ padding: 'var(--space-md)' }}>
              <div className="empty-state-sub">
                {isLiveMode && !hasRealData
                  ? 'No suspicious IP activity identified.'
                  : 'No source IP activity recorded.'}
              </div>
            </div>
          ) : (
            suspiciousIPs.slice(0, 5).map((ip, idx) => (
              <div key={ip.ip} className="ip-item">
                <span className="ip-rank">#{idx + 1}</span>
                <span className="ip-address">{ip.ip}</span>
                <SeverityBadge severity={ip.severity || ip.threatLevel || 'Low'} />
                <div className="ip-meta">
                  <span className="ip-count">{(ip.eventCount ?? ip.events ?? 0).toLocaleString()} events</span>
                  <span>{ip.topThreat || (ip.threats ? `${ip.threats} alert(s)` : 'Normal Traffic')}</span>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
