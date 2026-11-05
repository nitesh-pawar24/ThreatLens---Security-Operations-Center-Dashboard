// ThreatLens – Demo Data Module
// ⚠️  ALL DATA IS SIMULATED. This app does NOT monitor any real network or system.
// IP addresses use documentation ranges (192.0.2.x / TEST-NET-1, 198.51.100.x / TEST-NET-2,
// 203.0.113.x / TEST-NET-3) as specified in RFC 5737.

export const DEMO_NOTICE =
  "All data shown is simulated for demonstration purposes only. " +
  "ThreatLens does not monitor, scan, or access any real network or system.";

// ── Summary stats ────────────────────────────────────────────────────────────
export const summaryStats = {
  totalEvents: 14872,
  threatsDetected: 342,
  criticalAlerts: 27,
  uniqueIPs: 189,
};

// ── Activity chart data (last 14 days) ───────────────────────────────────────
export const activityData = [
  { date: "Oct 07", events: 820, threats: 18 },
  { date: "Oct 08", events: 1045, threats: 24 },
  { date: "Oct 09", events: 930, threats: 15 },
  { date: "Oct 10", events: 1120, threats: 31 },
  { date: "Oct 11", events: 760, threats: 12 },
  { date: "Oct 12", events: 680, threats: 9 },
  { date: "Oct 13", events: 590, threats: 7 },
  { date: "Oct 14", events: 1340, threats: 42 },
  { date: "Oct 15", events: 1180, threats: 38 },
  { date: "Oct 16", events: 975, threats: 27 },
  { date: "Oct 17", events: 1560, threats: 55 },
  { date: "Oct 18", events: 1220, threats: 33 },
  { date: "Oct 19", events: 890, threats: 19 },
  { date: "Oct 20", events: 1060, threats: 28 },
];

// ── Severity distribution ────────────────────────────────────────────────────
export const severityData = [
  { name: "Critical", value: 27, color: "#ef4444" },
  { name: "High", value: 89, color: "#f97316" },
  { name: "Medium", value: 156, color: "#eab308" },
  { name: "Low", value: 70, color: "#22c55e" },
];

// ── Alert severity constants ──────────────────────────────────────────────────
export const SEVERITY = {
  CRITICAL: "Critical",
  HIGH: "High",
  MEDIUM: "Medium",
  LOW: "Low",
};

export const STATUS = {
  OPEN: "Open",
  INVESTIGATING: "Investigating",
  RESOLVED: "Resolved",
  FALSE_POSITIVE: "False Positive",
};

// ── Recent alerts ─────────────────────────────────────────────────────────────
export const recentAlerts = [
  {
    id: "ALT-0001",
    timestamp: "2026-10-20 14:58:03",
    sourceIP: "203.0.113.42",
    eventType: "Brute Force – SSH",
    severity: SEVERITY.CRITICAL,
    status: STATUS.INVESTIGATING,
    details: "492 failed login attempts in 60 s from a single host.",
  },
  {
    id: "ALT-0002",
    timestamp: "2026-10-20 14:44:17",
    sourceIP: "198.51.100.77",
    eventType: "Port Scan Detected",
    severity: SEVERITY.HIGH,
    status: STATUS.OPEN,
    details: "Sequential port scan across 1–1024 detected.",
  },
  {
    id: "ALT-0003",
    timestamp: "2026-10-20 14:31:09",
    sourceIP: "192.0.2.15",
    eventType: "Malware Signature Match",
    severity: SEVERITY.CRITICAL,
    status: STATUS.OPEN,
    details: "File hash matched known ransomware signature (DEMO-HASH-001).",
  },
  {
    id: "ALT-0004",
    timestamp: "2026-10-20 14:22:55",
    sourceIP: "203.0.113.108",
    eventType: "Suspicious Outbound Traffic",
    severity: SEVERITY.HIGH,
    status: STATUS.INVESTIGATING,
    details: "Unusual data volume sent to external destination.",
  },
  {
    id: "ALT-0005",
    timestamp: "2026-10-20 14:10:41",
    sourceIP: "198.51.100.33",
    eventType: "SQL Injection Attempt",
    severity: SEVERITY.HIGH,
    status: STATUS.RESOLVED,
    details: "Classic UNION-based SQLi pattern in HTTP request body.",
  },
  {
    id: "ALT-0006",
    timestamp: "2026-10-20 13:58:22",
    sourceIP: "192.0.2.200",
    eventType: "Privilege Escalation",
    severity: SEVERITY.CRITICAL,
    status: STATUS.OPEN,
    details: "Unexpected sudo elevation by non-admin account.",
  },
  {
    id: "ALT-0007",
    timestamp: "2026-10-20 13:45:14",
    sourceIP: "203.0.113.19",
    eventType: "Repeated Auth Failure",
    severity: SEVERITY.MEDIUM,
    status: STATUS.RESOLVED,
    details: "12 consecutive failed logins from same IP.",
  },
  {
    id: "ALT-0008",
    timestamp: "2026-10-20 13:32:07",
    sourceIP: "198.51.100.55",
    eventType: "XSS Payload Detected",
    severity: SEVERITY.MEDIUM,
    status: STATUS.FALSE_POSITIVE,
    details: "Script tag detected in user-submitted form field.",
  },
  {
    id: "ALT-0009",
    timestamp: "2026-10-20 13:20:49",
    sourceIP: "192.0.2.88",
    eventType: "Policy Violation",
    severity: SEVERITY.LOW,
    status: STATUS.RESOLVED,
    details: "User accessed restricted resource outside business hours.",
  },
  {
    id: "ALT-0010",
    timestamp: "2026-10-20 13:07:31",
    sourceIP: "203.0.113.71",
    eventType: "DNS Tunnelling Suspected",
    severity: SEVERITY.HIGH,
    status: STATUS.INVESTIGATING,
    details: "Abnormally large DNS TXT record responses detected.",
  },
  {
    id: "ALT-0011",
    timestamp: "2026-10-20 12:55:18",
    sourceIP: "198.51.100.12",
    eventType: "Anomalous Login Location",
    severity: SEVERITY.MEDIUM,
    status: STATUS.OPEN,
    details: "Account logged in from two geographically distant locations in 30 min.",
  },
  {
    id: "ALT-0012",
    timestamp: "2026-10-20 12:43:02",
    sourceIP: "192.0.2.44",
    eventType: "File Integrity Violation",
    severity: SEVERITY.LOW,
    status: STATUS.RESOLVED,
    details: "Checksum mismatch on system configuration file.",
  },
];

// ── Top suspicious IPs ────────────────────────────────────────────────────────
export const suspiciousIPs = [
  {
    ip: "203.0.113.42",
    eventCount: 512,
    topThreat: "Brute Force – SSH",
    severity: SEVERITY.CRITICAL,
    firstSeen: "2026-10-20 08:12:44",
    lastSeen: "2026-10-20 14:58:03",
  },
  {
    ip: "198.51.100.77",
    eventCount: 278,
    topThreat: "Port Scan",
    severity: SEVERITY.HIGH,
    firstSeen: "2026-10-20 09:04:11",
    lastSeen: "2026-10-20 14:44:17",
  },
  {
    ip: "192.0.2.15",
    eventCount: 194,
    topThreat: "Malware Distribution",
    severity: SEVERITY.CRITICAL,
    firstSeen: "2026-10-20 10:22:30",
    lastSeen: "2026-10-20 14:31:09",
  },
  {
    ip: "203.0.113.108",
    eventCount: 143,
    topThreat: "Data Exfiltration",
    severity: SEVERITY.HIGH,
    firstSeen: "2026-10-20 11:45:00",
    lastSeen: "2026-10-20 14:22:55",
  },
  {
    ip: "203.0.113.71",
    eventCount: 97,
    topThreat: "DNS Tunnelling",
    severity: SEVERITY.HIGH,
    firstSeen: "2026-10-20 12:01:05",
    lastSeen: "2026-10-20 13:07:31",
  },
];

// ── Log analysis demo data ────────────────────────────────────────────────────
export const logEntries = [
  { id: "LOG-001", timestamp: "2026-10-20 14:59:01", level: "ERROR",   source: "auth-service",   message: "Authentication failure – user admin from 203.0.113.42" },
  { id: "LOG-002", timestamp: "2026-10-20 14:58:55", level: "WARN",    source: "firewall",        message: "Blocked inbound connection on port 22 from 203.0.113.42" },
  { id: "LOG-003", timestamp: "2026-10-20 14:58:12", level: "INFO",    source: "ids",             message: "Rule SSH_BRUTE_FORCE triggered for 203.0.113.42" },
  { id: "LOG-004", timestamp: "2026-10-20 14:47:30", level: "WARN",    source: "network-monitor", message: "Sequential port scan detected – source 198.51.100.77" },
  { id: "LOG-005", timestamp: "2026-10-20 14:32:10", level: "CRITICAL", source: "av-engine",      message: "Malware signature DEMO-HASH-001 matched on file transfer" },
  { id: "LOG-006", timestamp: "2026-10-20 14:23:05", level: "ERROR",   source: "dlp",             message: "High-volume outbound data transfer flagged for review" },
  { id: "LOG-007", timestamp: "2026-10-20 14:11:00", level: "WARN",    source: "waf",             message: "SQL injection pattern blocked in POST /api/login" },
  { id: "LOG-008", timestamp: "2026-10-20 13:59:10", level: "CRITICAL", source: "os-monitor",     message: "Unexpected privilege escalation on host DEMO-HOST-04" },
  { id: "LOG-009", timestamp: "2026-10-20 13:46:22", level: "INFO",    source: "auth-service",    message: "Account DEMO-USER-07 locked after 12 failures" },
  { id: "LOG-010", timestamp: "2026-10-20 13:33:44", level: "INFO",    source: "waf",             message: "XSS payload detected and sanitised in form submission" },
  { id: "LOG-011", timestamp: "2026-10-20 13:21:55", level: "INFO",    source: "policy-engine",   message: "Off-hours access attempt by DEMO-USER-03 – policy alert raised" },
  { id: "LOG-012", timestamp: "2026-10-20 13:08:02", level: "WARN",    source: "dns-monitor",     message: "Oversized TXT record response detected – possible DNS tunnel" },
];
