import { useState } from 'react';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Header from '@cloudscape-design/components/header';
import Container from '@cloudscape-design/components/container';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Input from '@cloudscape-design/components/input';
import Button from '@cloudscape-design/components/button';
import Alert from '@cloudscape-design/components/alert';
import { getBlastRadius } from '../services/api';
import Graph3D from '../components/Graph3D';

export default function BlastRadius() {
  const [resourceId, setResourceId] = useState('');
  const [loading, setLoading] = useState(false);
  const [impactedNodes, setImpactedNodes] = useState([]);
  const [error, setError] = useState(null);

  const handleAnalyze = async () => {
    if (!resourceId) return;
    setLoading(true);
    setError(null);
    try {
      const data = await getBlastRadius(resourceId);
      setImpactedNodes(data.impactedNodes || []);
    } catch (err) {
      setError('Failed to calculate blast radius. Resource may not exist or backend is unreachable.');
      // Mock data fallback if backend is down
      setImpactedNodes([
        { id: 'node-1', type: 'role', risk: 85 },
        { id: 'node-2', type: 'db', risk: 90 }
      ]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <ContentLayout header={<Header variant="h1" description="APT Kill Chain graph traversal · downstream impact analysis across converged multi-cloud topology">Blast Radius Engine</Header>}>
      <SpaceBetween size="l">
        <Container>
          <SpaceBetween size="m" direction="horizontal" alignItems="center">
            <Input
              value={resourceId}
              onChange={({ detail }) => setResourceId(detail.value)}
              placeholder="Enter Resource ID (e.g. i-0abcd1234)"
            />
            <Button variant="primary" onClick={handleAnalyze} loading={loading}>
              Analyze Impact
            </Button>
          </SpaceBetween>
          {error && <Alert type="error" header="Error" margin={{ top: 'm' }}>{error}</Alert>}
        </Container>

        {impactedNodes.length > 0 && (
          <Container header={<Header variant="h2">Impacted Convergence Topology — APT Propagation Path</Header>}>
            <div style={{ height: '500px' }}>
              <Graph3D nodes={impactedNodes} edges={[]} />
            </div>
          </Container>
        )}
      </SpaceBetween>
    </ContentLayout>
  );
}
