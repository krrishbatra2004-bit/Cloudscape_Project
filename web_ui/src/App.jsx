import { useState } from 'react';
import { Routes, Route } from 'react-router-dom';
import AppLayout from '@cloudscape-design/components/app-layout';
import TopNav from './components/TopNav';
import SideNav from './components/SideNav';
import Dashboard from './pages/Dashboard';
import InfrastructureMap from './pages/InfrastructureMap';
import BlastRadius from './pages/BlastRadius';
import ForensicTimeline from './pages/ForensicTimeline';
import SecurityEvents from './pages/SecurityEvents';

function App() {
  const [navigationOpen, setNavigationOpen] = useState(true);
  const [toolsOpen, setToolsOpen] = useState(false);

  return (
    <>
      <div id="h" style={{ position: 'sticky', top: 0, zIndex: 1002 }}>
        <TopNav />
      </div>
      <AppLayout
        navigationOpen={navigationOpen}
        onNavigationChange={({ detail }) => setNavigationOpen(detail.open)}
        toolsOpen={toolsOpen}
        onToolsChange={({ detail }) => setToolsOpen(detail.open)}
        navigation={<SideNav />}
        content={
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/map" element={<InfrastructureMap />} />
            <Route path="/blast-radius" element={<BlastRadius />} />
            <Route path="/timeline" element={<ForensicTimeline />} />
            <Route path="/events" element={<SecurityEvents />} />
          </Routes>
        }
        toolsHide={true}
        headerSelector="#h"
      />
    </>
  );
}

export default App;
