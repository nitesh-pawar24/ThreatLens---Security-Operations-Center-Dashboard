/**
 * IP Activity page – detailed view of top suspicious IPs with bar chart.
 * Integrated with the FastAPI detection engine via ThreatLensContext.
 */

import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from 'recharts';
import { Network, Info, Server, UploadCloud, WifiOff } from 'lucide-react';
import { useThreatLens } from '../context/ThreatLensContext';
import { DEMO_NOTICE } from '../data/demoData';
import { SeverityBadge } from '../components/Badges';

function CustomTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="custom-tooltip">
      <div className="custom-tooltip-label">{label}</div>
      {payload.map((p) => (
        <div key={p.dataKey} className="custom-tooltip-item">
          <span className="custom-tooltip-dot" style={{ background: p.fill }} />
          <span>Events: <strong>{(p.value ?? 0).toLocaleString()}</strong></span>
        </div>
      ))}
    </div>
  );
}

export default function IPActivityPage() {
  const { suspiciousIPs, isLiveMode, hasRealData, backendStatus, metadata } = useThreatLens();

  const chartData = suspiciousIPs.slice(0, 10).map((ip) => ({
    ip: ip.ip,
    events: ip.eventCount ?? ip.events ?? 0,
  }));

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
              <strong>Host Activity Analysis:</strong> Aggregated source metrics from{' '}
              <code>{metadata?.datasetName || 'uploaded file'}</code>.
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
            <span><strong>Live Mode — No Data:</strong> No suspicious IP activity identified. Upload security logs to identify suspicious addresses.</span>
          </div>
        )
      ) : (
        <div className="demo-notice-bar" role="note">
          <Info size={16} style={{ flexShrink: 0, marginTop: 2 }} aria-hidden="true" />
          <span>{DEMO_NOTICE} (Showing static demo IP data — switch to Live Mode to analyze real logs).</span>
        </div>
      )}

      {/* ── Live mode empty state ───────────────────────────────────────── */}
      {isLiveMode && !hasRealData ? (
        <div className="empty-state" style={{ padding: 'var(--space-xl)', textAlign: 'center' }}>
          <Network size={48} style={{ color: 'var(--text-muted)', marginBottom: 12 }} aria-hidden="true" />
          <div className="empty-state-title">No Suspicious IP Activity Identified</div>
          <div className="empty-state-sub">
            No source IP data available. Upload security logs via <strong>Log Analysis</strong> to identify suspicious addresses.
          </div>
        </div>
      ) : (
        <>
          {/* Bar chart */}
          <div className="panel" style={{ marginBottom: 'var(--space-xl)' }}>
            <div className="panel-title">
              <Network size={15} aria-hidden="true" />
              Event Count by Source IP (Top Active Hosts)
            </div>
            {chartData.length > 0 ? (
              <ResponsiveContainer width="100%" height={260}>
                <BarChart
                  data={chartData}
                  margin={{ top: 4, right: 8, left: -10, bottom: 25 }}
                >
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis
                    dataKey="ip"
                    tick={{ fontSize: 11, fontFamily: 'var(--font-mono)' }}
                    angle={-20}
                    textAnchor="end"
                    interval={0}
                  />
                  <YAxis tick={{ fontSize: 11 }} />
                  <Tooltip content={<CustomTooltip />} />
                  <Bar dataKey="events" name="Events" fill="#3b82f6" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="empty-state" style={{ height: 200, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <div className="empty-state-sub">No host activity data available.</div>
              </div>
            )}
          </div>

          {/* Detail cards */}
          <div className="section-heading">Address Details & Threat Ranking</div>
          <div className="ip-list">
            {suspiciousIPs.length === 0 ? (
              <div className="empty-state">
                <div className="empty-state-sub">No addresses recorded.</div>
              </div>
            ) : (
              suspiciousIPs.map((ip, idx) => (
                <div key={ip.ip} className="ip-item" style={{ flexWrap: 'wrap', gap: 'var(--space-md)' }}>
                  <span className="ip-rank">#{idx + 1}</span>
                  <div style={{ flex: 1, minWidth: 160 }}>
                    <div className="ip-address">{ip.ip}</div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
                      Top threat: {ip.topThreat || (ip.threats ? `${ip.threats} alert(s)` : 'Normal Traffic')}
                    </div>
                  </div>
                  <SeverityBadge severity={ip.severity || ip.threatLevel || 'Low'} />
                  <div className="ip-meta" style={{ minWidth: 160 }}>
                    <span className="ip-count">{(ip.eventCount ?? ip.events ?? 0).toLocaleString()} events</span>
                    {ip.firstSeen && <span>First seen: {ip.firstSeen}</span>}
                    {ip.lastSeen && <span>Last seen:  {ip.lastSeen}</span>}
                  </div>
                </div>
              ))
            )}
          </div>
        </>
      )}
    </div>
  );
}
