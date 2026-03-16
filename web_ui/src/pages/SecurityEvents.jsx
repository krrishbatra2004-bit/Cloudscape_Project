import { useState } from 'react';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Header from '@cloudscape-design/components/header';
import Table from '@cloudscape-design/components/table';
import TextFilter from '@cloudscape-design/components/text-filter';
import Pagination from '@cloudscape-design/components/pagination';
import Badge from '@cloudscape-design/components/badge';
import SpaceBetween from '@cloudscape-design/components/space-between';
import useStore from '../stores/useStore';

export default function SecurityEvents() {
  const { securityEvents } = useStore();
  const [filteringText, setFilteringText] = useState('');

  const items = securityEvents;

  const filteredItems = items.filter(item => 
    item.resource.toLowerCase().includes(filteringText.toLowerCase()) ||
    item.type.toLowerCase().includes(filteringText.toLowerCase())
  );

  return (
    <ContentLayout header={<Header variant="h1" description="Live feed of APT detection events, drift alerts, and cross-cloud security anomalies from the Sovereign-Forensic engine">Security Events & Alerts</Header>}>
      <Table
        columnDefinitions={[
          {
            id: 'timestamp',
            header: 'Timestamp',
            cell: item => new Date(item.timestamp).toLocaleString()
          },
          {
            id: 'resource',
            header: 'Resource',
            cell: item => item.resource
          },
          {
            id: 'type',
            header: 'Event Type',
            cell: item => item.type
          },
          {
            id: 'risk',
            header: 'Risk Score',
            cell: item => (
              <Badge color={item.risk > 80 ? 'red' : item.risk > 50 ? 'orange' : 'green'}>
                {item.risk}
              </Badge>
            )
          },
          {
            id: 'provider',
            header: 'Provider',
            cell: item => item.provider
          }
        ]}
        items={filteredItems}
        loadingText="Loading resources"
        trackBy="id"
        empty={
          <SpaceBetween direction="vertical" size="s">
            <b>No alerts found</b>
          </SpaceBetween>
        }
        filter={
          <TextFilter
            filteringPlaceholder="Find events"
            filteringText={filteringText}
            onChange={({ detail }) => setFilteringText(detail.filteringText)}
          />
        }
        pagination={<Pagination currentPageIndex={1} pagesCount={1} />}
      />
    </ContentLayout>
  );
}
