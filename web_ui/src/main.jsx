import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import '@cloudscape-design/global-styles/index.css';
import '@cloudscape-design/global-styles/dark-mode-utils.css';
import { applyMode, Mode } from '@cloudscape-design/global-styles';
import App from './App.jsx';
import './index.css';

// Apply dark mode theme
applyMode(Mode.Dark);

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </StrictMode>,
);
