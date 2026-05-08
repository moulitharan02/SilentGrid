import React, { useState, useEffect } from 'react';
import { Activity, ShieldAlert, Zap, Network } from 'lucide-react';
import Overview from './components/Overview';
import LiveFeed from './components/LiveFeed';
import ThreatMap from './components/ThreatMap';

function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [health, setHealth] = useState(null);

  useEffect(() => {
    fetch('/api/health')
      .then(res => res.json())
      .then(data => setHealth(data))
      .catch(console.error);
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh', width: '100vw' }}>
      <header style={{ background: '#0f172a', borderBottom: '1px solid #1e293b', padding: '1rem 2rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <ShieldAlert color="#ff4757" size={28} />
          <h1 style={{ margin: 0, fontSize: '1.5rem', fontWeight: 600, color: '#fff' }}>VulnXploit Core</h1>
          <span style={{ background: '#ff475720', color: '#ff4757', padding: '2px 8px', borderRadius: '12px', fontSize: '0.75rem', fontWeight: 600, marginLeft: '8px' }}>LIVE</span>
        </div>
        <div style={{ display: 'flex', gap: '16px', alignItems: 'center' }}>
          <div style={{ fontSize: '0.875rem', color: '#94a3b8' }}>
            ES Status: <span style={{ color: health?.elasticsearch ? '#10b981' : '#ef4444', fontWeight: 600 }}>{health?.elasticsearch ? 'CONNECTED' : 'OFFLINE'}</span>
          </div>
          <div style={{ fontSize: '0.875rem', color: '#94a3b8' }}>
            Engine: <span style={{ color: health?.status === 'ok' ? '#10b981' : '#ef4444', fontWeight: 600 }}>{health?.status === 'ok' ? 'ONLINE' : 'ERROR'}</span>
          </div>
        </div>
      </header>
      
      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
        <aside style={{ width: '240px', background: '#0f172a', borderRight: '1px solid #1e293b', display: 'flex', flexDirection: 'column' }}>
          <nav style={{ padding: '1rem', display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <NavButton icon={<Activity />} label="Overview" active={activeTab === 'overview'} onClick={() => setActiveTab('overview')} />
            <NavButton icon={<Zap />} label="Live Feed" active={activeTab === 'live'} onClick={() => setActiveTab('live')} />
            <NavButton icon={<Network />} label="Threat Map" active={activeTab === 'map'} onClick={() => setActiveTab('map')} />
          </nav>
        </aside>

        <main style={{ flex: 1, padding: '2rem', overflowY: 'auto', background: '#0a0f1e' }}>
          {activeTab === 'overview' && <Overview />}
          {activeTab === 'live' && <LiveFeed />}
          {activeTab === 'map' && <ThreatMap />}
        </main>
      </div>
    </div>
  );
}

function NavButton({ icon, label, active, onClick }) {
  return (
    <button
      onClick={onClick}
      style={{
        display: 'flex', alignItems: 'center', gap: '12px', padding: '12px 16px',
        background: active ? '#1e293b' : 'transparent',
        color: active ? '#fff' : '#94a3b8',
        border: 'none', borderRadius: '8px', cursor: 'pointer',
        fontSize: '1rem', fontWeight: 500, textAlign: 'left',
        transition: 'all 0.2s'
      }}
      onMouseOver={(e) => { if (!active) { e.currentTarget.style.background = '#1e293b80'; e.currentTarget.style.color = '#fff'; } }}
      onMouseOut={(e) => { if (!active) { e.currentTarget.style.background = 'transparent'; e.currentTarget.style.color = '#94a3b8'; } }}
    >
      {React.cloneElement(icon, { size: 20 })}
      {label}
    </button>
  );
}

export default App;
