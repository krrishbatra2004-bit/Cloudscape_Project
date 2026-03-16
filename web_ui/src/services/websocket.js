import useStore from '../stores/useStore';

class WebSocketService {
  constructor() {
    this.ws = null;
    this.reconnectTimeout = null;
  }

  connect() {
    if (this.ws) {
      this.ws.close();
    }

    this.ws = new WebSocket('ws://localhost:4000');

    this.ws.onopen = () => {
      console.log('WebSocket connected');
      useStore.getState().setWebsocketConnected(true);
      if (this.reconnectTimeout) {
        clearTimeout(this.reconnectTimeout);
        this.reconnectTimeout = null;
      }
    };

    this.ws.onmessage = (event) => {
      try {
        const message = JSON.parse(event.data);
        console.log('WS Message:', message);
        useStore.getState().addEvent(message);
        
        // Refresh graph if new asset or changed topology
        if (message.type === 'asset:new' || message.type === 'topology:updated') {
          // Here we would typically trigger an API re-fetch or apply delta.
          // In a real app we'd dispatch a thunk/action.
        }
      } catch (err) {
        console.error('WebSocket message parsing error', err);
      }
    };

    this.ws.onclose = () => {
      console.log('WebSocket disconnected');
      useStore.getState().setWebsocketConnected(false);
      // Auto reconnect
      this.reconnectTimeout = setTimeout(() => this.connect(), 5000);
    };

    this.ws.onerror = (err) => {
      console.error('WebSocket error:', err);
      this.ws.close();
    };
  }

  disconnect() {
    if (this.ws) {
      this.ws.close();
    }
    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout);
    }
  }
}

export const wsService = new WebSocketService();
