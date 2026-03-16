import { useState, useEffect } from 'react';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Header from '@cloudscape-design/components/header';
import Container from '@cloudscape-design/components/container';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Slider from '@cloudscape-design/components/slider';
import Table from '@cloudscape-design/components/table';
import { getTimeline } from '../services/api';

export default function ForensicTimeline() {
  const [snapshots, setSnapshots] = useState([]);
  const [currentIndex, setCurrentIndex] = useState(0);

  useEffect(() => {
    // Fetch real timeline or use mock
    getTimeline().then(data => {
      setSnapshots(data.snapshots || []);
    }).catch(err => {
      console.error('Failed to load timeline', err);
    });
  }, []);

  const currentSnapshot = snapshots[currentIndex] || { mutations: [] };

  return (
    <ContentLayout header={<Header variant="h1" description="State-Factory time-travel · infrastructure state snapshots · mutation audit trail across all 7 tenants">Forensic Timeline</Header>}>
      <SpaceBetween size="l">
        <Container header={<Header variant="h2">Infrastructure State Snapshot Selector</Header>}>
          <Slider
            max={Math.max(0, snapshots.length - 1)}
            min={0}
            value={currentIndex}
            onChange={({ detail }) => setCurrentIndex(detail.value)}
            valueFormatter={(val) => snapshots[val] ? new Date(snapshots[val].timestamp).toLocaleString() : ''}
          />
        </Container>

        <Container header={<Header variant="h2">State Mutations at Selected Timestamp</Header>}>
          <Table
            columnDefinitions={[
              { id: 'type', header: 'Mutation Type', cell: e => e.type },
              { id: 'resource', header: 'Resource', cell: e => e.resource },
              { id: 'desc', header: 'Description', cell: e => e.desc || '-' }
            ]}
            items={currentSnapshot.mutations}
            empty="No mutations in this snapshot"
          />
        </Container>
      </SpaceBetween>
    </ContentLayout>
  );
}
