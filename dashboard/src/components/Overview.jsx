import React, { useEffect, useState } from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';
import { Shield, AlertTriangle, AlertOctagon, Info } from 'lucide-react';

const COLORS = {
  CRITICAL: '#ff4757',
  HIGH: '#ffa502',
  MEDIUM: '#eccc68',
  LOW: '#1e90ff'
};

export default function Overview() {
  const [summary, setSummary] = useState(null);

  useEffect(() => {
    fetch('/api/detections/summary?hours=24')
      .then(r => r.json())
      .then(data => setSummary(data))
      .catch(console.error);
    
    const interval = setInterval(() => {
      fetch('/api/detections/summary?hours=24')
        .then(r => r.json())
        .then(data => setSummary(data))
        .catch(console.error);
    }, 10000);
    return () => clearInterval(interval);
  }, []);

  if (!summary) return <div>Loading overview...</div>;

  const pieData = Object.entries(summary.by_severity).map(([name, value]) => ({ name, value }));

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
      <h2 style={{ margin: 0, fontSize: '1.5rem', fontWeight: 600 }}>Security Overview (Last 24h)</h2>
      
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '1.5rem' }}>
        <StatCard title="Total Detections" value={summary.total_detections} icon={<Shield size={24} color="#1e90ff" />} />
        <StatCard title="Critical Alerts" value={summary.by_severity.CRITICAL || 0} icon={<AlertOctagon size={24} color="#ff4757" />} />
        <StatCard title="High Risk Alerts" value={summary.by_severity.HIGH || 0} icon={<AlertTriangle size={24} color="#ffa502" />} />
        <StatCard title="Avg Risk Score" value={summary.avg_risk_score} icon={<Info size={24} color="#eccc68" />} />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
        <div style={{ background: '#0f172a', padding: '1.5rem', borderRadius: '12px', border: '1px solid #1e293b' }}>
          <h3 style={{ margin: '0 0 1rem 0', color: '#94a3b8' }}>Detections by Severity</h3>
          <div style={{ height: '300px' }}>
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={pieData} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius={60} outerRadius={100} label>
                  {pieData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[entry.name] || '#ccc'} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px' }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div style={{ background: '#0f172a', padding: '1.5rem', borderRadius: '12px', border: '1px solid #1e293b' }}>
          <h3 style={{ margin: '0 0 1rem 0', color: '#94a3b8' }}>Top Source IPs</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            {summary.top_src_ips.map((item, i) => (
              <div key={i} style={{ display: 'flex', justifyContent: 'space-between', padding: '0.75rem', background: '#1e293b', borderRadius: '6px' }}>
                <span style={{ fontFamily: 'monospace' }}>{item.ip}</span>
                <span style={{ color: '#ff4757', fontWeight: 600 }}>{item.count}</span>
              </div>
            ))}
            {summary.top_src_ips.length === 0 && <div style={{ color: '#64748b' }}>No detections found.</div>}
          </div>
        </div>
      </div>
    </div>
  );
}

function StatCard({ title, value, icon }) {
  return (
    <div style={{ background: '#0f172a', padding: '1.5rem', borderRadius: '12px', border: '1px solid #1e293b', display: 'flex', alignItems: 'center', gap: '1rem' }}>
      <div style={{ background: '#1e293b', padding: '1rem', borderRadius: '12px' }}>
        {icon}
      </div>
      <div>
        <div style={{ color: '#94a3b8', fontSize: '0.875rem', marginBottom: '4px' }}>{title}</div>
        <div style={{ fontSize: '1.75rem', fontWeight: 700, color: '#fff' }}>{value}</div>
      </div>
    </div>
  );
}
