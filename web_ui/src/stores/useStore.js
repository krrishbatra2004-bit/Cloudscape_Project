import { create } from 'zustand';

const useStore = create((set) => ({
  // Graph state
  nodes: [],
  edges: [],
  selectedNode: null,
  
  // App state
  websocketConnected: false,
  driftEvents: [],
  securityEvents: [],
  metrics: {
    totalAssets: 0,
    driftCount: 0,
    alertCount: 0,
    activeConnections: 0
  },

  // Actions
  setGraph: (nodes, edges) => set({ nodes, edges, metrics: (prev) => ({ ...prev, totalAssets: nodes.length }) }),
  setSelectedNode: (node) => set({ selectedNode: node }),
  setWebsocketConnected: (status) => set({ websocketConnected: status }),
  
  addEvent: (event) => set((state) => {
    if (event.type === 'drift:detected') {
      return { 
        driftEvents: [event.payload, ...state.driftEvents].slice(0, 100),
        metrics: { ...state.metrics, driftCount: state.metrics.driftCount + 1 }
      };
    }
    if (event.type === 'alert:security') {
      return { 
        securityEvents: [event.payload, ...state.securityEvents].slice(0, 100),
        metrics: { ...state.metrics, alertCount: state.metrics.alertCount + 1 }
      };
    }
    return state;
  }),
  
  updateMetrics: (newMetrics) => set((state) => ({ metrics: { ...state.metrics, ...newMetrics } }))
}));

export default useStore;
