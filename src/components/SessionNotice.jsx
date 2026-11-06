/**
 * ThreatLens – SessionNotice
 * Shown when the backend expired the visitor's private session and replaced it with a
 * fresh, empty one, so the visitor understands why their uploaded data is gone.
 */

import { Info, X } from 'lucide-react';
import { useThreatLens } from '../context/ThreatLensContext';

export default function SessionNotice() {
  const { sessionNotice, clearSessionNotice } = useThreatLens();
  if (!sessionNotice) return null;

  return (
    <div style={{ padding: 'var(--space-lg) var(--space-lg) 0', flexShrink: 0 }}>
    <div
      className="demo-notice-bar"
      role="status"
      style={{ background: 'rgba(59,130,246,0.08)', border: '1px solid rgba(59,130,246,0.25)', color: '#93c5fd' }}
    >
      <Info size={16} style={{ flexShrink: 0, marginTop: 2 }} aria-hidden="true" />
      <span style={{ flex: 1 }}>{sessionNotice}</span>
      <button
        type="button"
        onClick={clearSessionNotice}
        aria-label="Dismiss session notice"
        style={{ background: 'none', border: 'none', color: 'inherit', cursor: 'pointer', padding: 0, display: 'flex' }}
      >
        <X size={14} aria-hidden="true" />
      </button>
    </div>
    </div>
  );
}
