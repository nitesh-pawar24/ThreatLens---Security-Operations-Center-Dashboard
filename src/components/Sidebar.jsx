import { Shield } from 'lucide-react';
import { LayoutDashboard, Bell, FileText, Network, Settings } from 'lucide-react';
import { useThreatLens } from '../context/ThreatLensContext';

const NAV_ITEMS = [
  { id: 'overview',     label: 'Overview',     icon: LayoutDashboard },
  { id: 'alerts',       label: 'Alerts',       icon: Bell            },
  { id: 'logs',         label: 'Log Analysis', icon: FileText        },
  { id: 'ip-activity',  label: 'IP Activity',  icon: Network         },
  { id: 'settings',     label: 'Settings',     icon: Settings        },
];

export default function Sidebar({ activePage, onNavigate }) {
  const { appMode, alerts } = useThreatLens();
  const alertCount = alerts.length > 0 ? alerts.length : null;

  return (
    <aside className="sidebar" role="navigation" aria-label="Main navigation">
      {/* Brand */}
      <div className="sidebar-brand">
        <div className="brand-icon" aria-hidden="true">
          <Shield size={20} />
        </div>
        <div className="brand-text">
          <div className="brand-name">ThreatLens</div>
          <div className="brand-sub">Security Ops Center</div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="sidebar-nav">
        <div className="nav-section-label">Navigation</div>
        {NAV_ITEMS.map(({ id, label, icon: Icon }) => {
          const badge = id === 'alerts' ? alertCount : null;
          return (
            <button
              key={id}
              className={`nav-item${activePage === id ? ' active' : ''}`}
              onClick={() => onNavigate(id)}
              aria-current={activePage === id ? 'page' : undefined}
              title={label}
            >
              <Icon size={16} aria-hidden="true" />
              <span>{label}</span>
              {badge !== null && (
                <span className="nav-badge" aria-label={`${badge} alerts`}>
                  {badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Footer */}
      <div className="sidebar-footer">
        <div className="sidebar-version">
          v1.0 · {appMode === 'live' ? 'Live Mode' : 'Demo Mode'}
        </div>
      </div>
    </aside>
  );
}
