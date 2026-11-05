/**
 * Reusable badge components used across the dashboard.
 */

const SEVERITY_CLASS = {
  Critical: 'badge-critical',
  High:     'badge-high',
  Medium:   'badge-medium',
  Low:      'badge-low',
};

const STATUS_CLASS = {
  'Open':           'status-open',
  'Investigating':  'status-investigating',
  'Resolved':       'status-resolved',
  'False Positive': 'status-fp',
};

export function SeverityBadge({ severity }) {
  const cls = SEVERITY_CLASS[severity] ?? 'badge-low';
  return (
    <span className={`badge ${cls}`} aria-label={`Severity: ${severity}`}>
      {severity}
    </span>
  );
}

export function StatusBadge({ status }) {
  const cls  = STATUS_CLASS[status] ?? 'status-fp';
  return (
    <span className={`status-badge ${cls}`} aria-label={`Status: ${status}`}>
      {status}
    </span>
  );
}

const PRIORITY_CLASS = {
  Critical: 'priority-critical',
  High:     'priority-high',
  Medium:   'priority-medium',
  Low:      'priority-low',
};

export function PriorityBadge({ priority }) {
  const label = priority || 'Low';
  const cls = PRIORITY_CLASS[label] ?? 'priority-low';
  return (
    <span className={`priority-badge ${cls}`} aria-label={`Priority: ${label}`}>
      <span className="priority-dot" />
      {label}
    </span>
  );
}

export function RiskScoreBadge({ score, priority }) {
  const val = typeof score === 'number' ? Math.round(score) : 0;
  let level = 'low';
  if (val >= 80) level = 'critical';
  else if (val >= 60) level = 'high';
  else if (val >= 35) level = 'medium';

  return (
    <div className={`risk-score-pill risk-score-${level}`} title={`Risk Score: ${val}/100 (${priority || level})`}>
      <span className="risk-score-num">{val}</span>
      <span className="risk-score-max">/100</span>
    </div>
  );
}
