import SideNavigation from '@cloudscape-design/components/side-navigation';
import { useLocation, useNavigate } from 'react-router-dom';

export default function SideNav() {
  const location = useLocation();
  const navigate = useNavigate();

  return (
    <SideNavigation
      activeHref={location.pathname}
      header={{ href: '/', text: 'CloudSCAPE' }}
      onFollow={(e) => {
        if (!e.detail.external) {
          e.preventDefault();
          navigate(e.detail.href);
        }
      }}
      items={[
        { type: 'link', text: 'Mission Dashboard', href: '/' },
        { type: 'link', text: 'Multi-Cloud Topology', href: '/map' },
        { type: 'link', text: 'Blast Radius Engine', href: '/blast-radius' },
        { type: 'link', text: 'Forensic Timeline', href: '/timeline' },
        { type: 'link', text: 'Security Events & Alerts', href: '/events' },
        { type: 'divider' },
        {
          type: 'link',
          text: 'Documentation',
          href: 'https://docs.aws.amazon.com/',
          external: true
        }
      ]}
    />
  );
}
