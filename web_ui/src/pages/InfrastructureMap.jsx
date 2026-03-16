import { useEffect } from 'react';
import useStore from '../stores/useStore';
import { getGraph } from '../services/api';
import Graph3D from '../components/Graph3D';
import NodePanel from '../components/NodePanel';
import Header from '@cloudscape-design/components/header';

// =============================================================================
// LEGEND – explains the map to non-technical users
// =============================================================================
const legendStyle = {
  position: 'absolute',
  bottom: '20px',
  left: '20px',
  background: 'rgba(10, 17, 26, 0.92)',
  border: '1px solid rgba(0, 161, 255, 0.3)',
  borderRadius: '10px',
  padding: '16px 20px',
  color: '#ccdae8',
  fontSize: '12px',
  lineHeight: '1.7',
  zIndex: 10,
  maxWidth: '320px',
  backdropFilter: 'blur(8px)',
};

const dotStyle = (color) => ({
  display: 'inline-block',
  width: 10,
  height: 10,
  borderRadius: '50%',
  background: color,
  marginRight: 8,
  verticalAlign: 'middle',
  boxShadow: `0 0 6px ${color}`,
});

const lineStyle = {
  display: 'inline-block',
  width: 20,
  height: 2,
  background: '#00a1ff',
  marginRight: 8,
  verticalAlign: 'middle',
  boxShadow: '0 0 4px #00a1ff',
};

function MapLegend({ nodeCount, edgeCount }) {
  return (
    <div style={legendStyle}>
      <div style={{ fontWeight: 'bold', fontSize: 14, marginBottom: 8, color: '#ffffff' }}>
        📘 How to Read This Map
      </div>

      <div style={{ marginBottom: 10, color: '#8899aa' }}>
        Each sphere is a <strong style={{ color: '#fff' }}>cloud resource</strong> — 
        a computer, database, storage, or security rule running in the cloud.
        Click any sphere to see its details.
      </div>

      <div style={{ fontWeight: 'bold', marginBottom: 4, color: '#ffffff' }}>Node Colors</div>
      <div><span style={dotStyle('#fbbf24')}></span>AWS (Amazon) resource</div>
      <div><span style={dotStyle('#0ea5e9')}></span>Azure (Microsoft) resource</div>
      <div><span style={dotStyle('#3b82f6')}></span>Other cloud provider</div>
      <div><span style={dotStyle('#f97316')}></span>⚠️ Medium risk (score 51–80)</div>
      <div><span style={dotStyle('#ef4444')}></span>🚨 High risk (score 81–100)</div>

      <div style={{ fontWeight: 'bold', marginTop: 10, marginBottom: 4, color: '#ffffff' }}>Connections</div>
      <div>
        <span style={lineStyle}></span>
        A blue line between two spheres means they are <strong style={{ color: '#fff' }}>connected</strong> — 
        one resource can access, control, or depend on the other. 
        These connections are what attackers follow to move through your infrastructure.
      </div>

      <div style={{ marginTop: 10, color: '#667788', fontSize: 11 }}>
        Showing {nodeCount.toLocaleString()} of 5,082+ resources · {edgeCount.toLocaleString()} connections
      </div>
    </div>
  );
}

// =============================================================================
// PAGE
// =============================================================================
export default function InfrastructureMap() {
  const { nodes, edges, setGraph } = useStore();

  useEffect(() => {
    getGraph().then(data => {
      setGraph(data.nodes || [], data.edges || []);
    }).catch(err => {
      console.error('Failed to load graph, API is unavailable', err);
    });
  }, [setGraph]);

  return (
    <div style={{ padding: '0 20px 20px 20px', height: '100%', position: 'relative' }}>
      <Header variant="h1" description="Live 3D topology map of 5,082+ merged nodes across 7 tenants · Hybrid Convergence Bridge · MOCK Mode">
        Multi-Cloud Infrastructure Topology
      </Header>
      
      <div className="canvas-container" style={{ marginTop: '20px', position: 'relative' }}>
        <Graph3D nodes={nodes} edges={edges} />
        <MapLegend nodeCount={Math.min(nodes.length, 500)} edgeCount={edges.length} />
      </div>

      <NodePanel />
    </div>
  );
}
