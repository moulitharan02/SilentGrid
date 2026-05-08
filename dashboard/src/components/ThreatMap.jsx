import React, { useState, useEffect, useRef } from 'react';
import ForceGraph2D from 'react-force-graph-2d';

export default function ThreatMap() {
  const [graphData, setGraphData] = useState({ nodes: [], edges: [] });
  const containerRef = useRef(null);
  const [dimensions, setDimensions] = useState({ width: 800, height: 600 });

  useEffect(() => {
    fetch('/api/graph?hours=24&min_risk=50')
      .then(r => r.json())
      .then(data => {
        // format for force graph
        const gData = {
          nodes: data.nodes.map(n => ({ id: n.id, c2: n.c2, risk: n.risk, val: n.count })),
          links: data.edges.map(e => ({ source: e.source, target: e.target, risk: e.risk }))
        };
        setGraphData(gData);
      })
      .catch(console.error);
      
    if (containerRef.current) {
      setDimensions({
        width: containerRef.current.clientWidth,
        height: containerRef.current.clientHeight
      });
    }
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', gap: '1rem' }}>
      <h2 style={{ margin: 0, fontSize: '1.5rem', fontWeight: 600 }}>C2 Threat Map (High Risk)</h2>
      <div ref={containerRef} style={{ flex: 1, background: '#0f172a', borderRadius: '12px', border: '1px solid #1e293b', overflow: 'hidden' }}>
        <ForceGraph2D
          width={dimensions.width}
          height={dimensions.height}
          graphData={graphData}
          nodeLabel="id"
          nodeColor={node => node.c2 ? '#ff4757' : (node.risk > 75 ? '#ffa502' : '#1e90ff')}
          nodeRelSize={6}
          linkColor={() => 'rgba(255,255,255,0.2)'}
          linkDirectionalParticles={2}
          linkDirectionalParticleSpeed={d => d.risk * 0.001}
          backgroundColor="#0f172a"
        />
      </div>
    </div>
  );
}
