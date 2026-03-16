import TopNavigation from '@cloudscape-design/components/top-navigation';

export default function TopNav() {
  return (
    <TopNavigation
      identity={{
        href: '/',
        title: <span className="cloudscape-vibrant-title">CloudSCAPE</span>,
        logo: {
          src: 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSIjZmZmZmZmIiBzdHJva2Utd2lkdGg9IjIiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCIgc3Ryb2tlLWxpbmVqb2luPSJyb3VuZCI+PHBhdGggZD0iTTEyIDJMMiA3bDEwIDUgMTAtNS0xMC01ek0yIDE3bDEwIDUgMTAtNU0yIDEybDEwIDUgMTAtNSIvPjwvc3ZnPg==',
          alt: 'CloudScape Nexus Logo'
        }
      }}
      utilities={[
        {
          type: 'button',
          text: 'Alerts',
          iconName: 'notification',
          badge: true
        },
        {
          type: 'menu-dropdown',
          text: 'SOC Admin',
          description: 'Sovereign-Forensic Multi-Cloud Intelligence Mesh · v5.2 Titan',
          iconName: 'user-profile',
          items: [
            { id: 'settings', text: 'Settings' },
            { id: 'signout', text: 'Sign out' }
          ]
        }
      ]}
      i18nStrings={{
        searchIconAriaLabel: 'Search',
        searchDismissIconAriaLabel: 'Close search',
        overflowMenuTriggerText: 'More'
      }}
    />
  );
}
