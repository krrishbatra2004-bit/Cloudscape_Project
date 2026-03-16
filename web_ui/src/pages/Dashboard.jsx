import { useState, useEffect, useMemo } from 'react';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Header from '@cloudscape-design/components/header';
import Container from '@cloudscape-design/components/container';
import Grid from '@cloudscape-design/components/grid';
import ColumnLayout from '@cloudscape-design/components/column-layout';
import Box from '@cloudscape-design/components/box';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Table from '@cloudscape-design/components/table';
import BarChart from '@cloudscape-design/components/bar-chart';
import useStore from '../stores/useStore';
import { getGraph } from '../services/api';

export default function Dashboard() {
  const { nodes, metrics, securityEvents, setGraph } = useStore();
  
  useEffect(() => {
    if (nodes.length === 0) {
      getGraph().then(data => {
        setGraph(data.nodes || [], data.edges || []);
      }).catch(err => {
        console.error('API Error:', err);
      });
    }
  }, [nodes.length, setGraph]);

  const providerData = useMemo(() => {
    if (!nodes || nodes.length === 0) return [];

    const summary = {};
    nodes.forEach(n => {
      const p = n.provider || 'unknown';
      const t = n.type || 'unknown';
      if (!summary[p]) summary[p] = {};
      summary[p][t] = (summary[p][t] || 0) + 1;
    });

    return Object.keys(summary).map(p => {
      return {
        title: p.toUpperCase(),
        type: 'bar',
        data: Object.keys(summary[p]).map(t => ({ x: t, y: summary[p][t] }))
      };
    });
  }, [nodes]);

  return (
    <ContentLayout
      header={<Header variant="h1" description="Sovereign-Forensic Multi-Cloud Intelligence Mesh · Nexus 5.2 Titan · MOCK Mode">Mission Control Dashboard</Header>}
    >
      <SpaceBetween size="l">
        <Grid
          gridDefinition={[{ colspan: 3 }, { colspan: 3 }, { colspan: 3 }, { colspan: 3 }]}
        >
          <Container fitHeight>
            <Box variant="h3">Total Cloud Assets</Box>
            <Box variant="h1">{nodes.length > 0 ? nodes.length : (metrics.totalAssets || 435)}</Box>
          </Container>
          <Container fitHeight>
            <Box variant="h3">Drift Events (24h)</Box>
            <Box variant="h1" color="text-status-warning">{metrics.driftCount || 0}</Box>
          </Container>
          <Container fitHeight>
            <Box variant="h3">Security Alerts</Box>
            <Box variant="h1" color="text-status-error">{metrics.alertCount || 0}</Box>
          </Container>
          <Container fitHeight>
            <Box variant="h3">Active Connections</Box>
            <Box variant="h1" color="text-status-success">{metrics.activeConnections || 0}</Box>
          </Container>
        </Grid>

        <ColumnLayout columns={2} variant="text-grid">
          <Container header={<Header variant="h2">Hybrid Cloud Provider Distribution</Header>}>
            <BarChart
              series={providerData}
              xDomain={providerData.flatMap(p => p.data.map(d => d.x)).filter((v, i, a) => a.indexOf(v) === i)}
              yDomain={[0, Math.max(...providerData.flatMap(p => p.data.map(d => d.y)), 10) * 1.2]}
              empty={<Box textAlign="center" color="inherit"><b>No data</b></Box>}
              height={300}
            />
          </Container>
          
          <Container header={<Header variant="h2">Recent Security Events & Drift Detections</Header>}>
            <Table
              columnDefinitions={[
                { id: 'time', header: 'Time', cell: e => new Date(e.timestamp || Date.now()).toLocaleTimeString() },
                { id: 'type', header: 'Event', cell: e => e.type || 'Unknown' },
                { id: 'resource', header: 'Resource', cell: e => e.resource || 'N/A' }
              ]}
              items={securityEvents.slice(0, 5)}
              empty={
                <Box margin={{ vertical: "xs" }} textAlign="center" color="inherit">
                  <SpaceBetween size="m">
                    <b>No recent events</b>
                  </SpaceBetween>
                </Box>
              }
            />
          </Container>
        </ColumnLayout>
      </SpaceBetween>
    </ContentLayout>
  );
}
