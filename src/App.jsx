/**
 * ThreatLens – App root
 * Manages navigation state and wraps the application with ThreatLensProvider.
 */

import { useState } from 'react';
import Sidebar        from './components/Sidebar';
import Header         from './components/Header';
import OverviewPage   from './pages/OverviewPage';
import AlertsPage     from './pages/AlertsPage';
import LogsPage       from './pages/LogsPage';
import IPActivityPage from './pages/IPActivityPage';
import SettingsPage   from './pages/SettingsPage';
import { ThreatLensProvider } from './context/ThreatLensContext';

const PAGES = {
  overview:      OverviewPage,
  alerts:        AlertsPage,
  logs:          LogsPage,
  'ip-activity': IPActivityPage,
  settings:      SettingsPage,
};

export default function App() {
  const [activePage, setActivePage] = useState('overview');

  const PageComponent = PAGES[activePage] ?? OverviewPage;

  return (
    <ThreatLensProvider>
      <div className="app-shell">
        <Sidebar activePage={activePage} onNavigate={setActivePage} />
        <div className="main-area">
          <Header activePage={activePage} />
          <PageComponent />
        </div>
      </div>
    </ThreatLensProvider>
  );
}
