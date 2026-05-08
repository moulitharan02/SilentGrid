import React, { useState, useEffect } from 'react';

const COLORS = {
  CRITICAL: '#ff4757',
  HIGH: '#ffa502',
  MEDIUM: '#eccc68',
  LOW: '#1e90ff'
};

export default function LiveFeed() {
  const [events, setEvents] = useState([]);
  const [originFilter, setOriginFilter] = useState('');

  useEffect(() => {
    const fetchEvents = () => {
      fetch('/api/detections?limit=50')
        .then(r => r.json())
        .then(data => setEvents(data))
        .catch(console.error);
    };
    
    fetchEvents();
    const interval = setInterval(fetchEvents, 5000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h2 style={{ margin: 0, fontSize: '1.5rem', fontWeight: 600 }}>Live Detection Feed</h2>
        <input 
          type="text" 
          placeholder="Filter by Origin IP..." 
          value={originFilter}
          onChange={e => setOriginFilter(e.target.value)}
          style={{ padding: '8px 12px', borderRadius: '6px', border: '1px solid #1e293b', background: '#0f172a', color: '#fff', outline: 'none' }}
        />
      </div>
      
      <div style={{ background: '#0f172a', borderRadius: '12px', border: '1px solid #1e293b', overflow: 'hidden' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
          <thead>
            <tr style={{ background: '#1e293b', color: '#94a3b8', fontSize: '0.875rem' }}>
              <th style={{ padding: '1rem' }}>Timestamp</th>
              <th style={{ padding: '1rem' }}>Source IP:Port</th>
              <th style={{ padding: '1rem' }}>Dest IP:Port</th>
              <th style={{ padding: '1rem' }}>Prediction</th>
              <th style={{ padding: '1rem' }}>Severity</th>
              <th style={{ padding: '1rem' }}>Risk Score</th>
            </tr>
          </thead>
          <tbody>
            {events.filter(evt => !originFilter || evt.src_ip.includes(originFilter)).map((evt, i) => (
              <tr key={i} style={{ borderBottom: '1px solid #1e293b', background: i % 2 === 0 ? '#0f172a' : '#0a0f1e' }}>
                <td style={{ padding: '1rem', color: '#94a3b8' }}>{new Date(evt.timestamp).toLocaleTimeString()}</td>
                <td style={{ padding: '1rem', fontFamily: 'monospace' }}>{evt.src_ip}{evt.src_port ? `:${evt.src_port}` : ''}</td>
                <td style={{ padding: '1rem', fontFamily: 'monospace' }}>{evt.dst_ip}{evt.dst_port ? `:${evt.dst_port}` : ''}</td>
                <td style={{ padding: '1rem', fontWeight: 500 }}>{evt.prediction}</td>
                <td style={{ padding: '1rem' }}>
                  <span style={{ 
                    padding: '4px 8px', borderRadius: '4px', fontSize: '0.75rem', fontWeight: 600,
                    background: `${COLORS[evt.severity]}20`, color: COLORS[evt.severity] || '#fff'
                  }}>
                    {evt.severity}
                  </span>
                </td>
                <td style={{ padding: '1rem', fontWeight: 600, color: evt.risk_score > 70 ? '#ff4757' : '#e2e8f0' }}>
                  {evt.risk_score.toFixed(1)}
                </td>
              </tr>
            ))}
            {events.length === 0 && (
              <tr><td colSpan="6" style={{ padding: '2rem', textAlign: 'center', color: '#64748b' }}>No live events...</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
