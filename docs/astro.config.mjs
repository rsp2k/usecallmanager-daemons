// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// https://astro.build/config
export default defineConfig({
  site: 'https://docs.usecallmanager-services.l.supported.systems',
  telemetry: false,
  integrations: [
    starlight({
      title: 'UseCallManager',
      description: 'Documentation for Cisco IP Phone security services',
      social: [
        { icon: 'github', label: 'GitHub', href: 'https://github.com/rsp2k/usecallmanager-daemons' },
      ],
      sidebar: [
        {
          label: 'Getting Started',
          items: [
            { label: 'Introduction', slug: 'index' },
          ],
        },
        {
          label: 'Tutorials',
          badge: { text: 'Learning', variant: 'success' },
          items: [
            { label: 'Your First Phone Deployment', slug: 'tutorials/first-deployment' },
          ],
        },
        {
          label: 'How-To Guides',
          badge: { text: 'Tasks', variant: 'tip' },
          collapsed: false,
          items: [
            {
              label: 'Installation',
              collapsed: true,
              items: [
                { label: 'Deploy with Docker Compose', slug: 'how-to/installation/deploy-docker' },
                { label: 'Configure Environment', slug: 'how-to/installation/configure-environment' },
                { label: 'Backup & Restore', slug: 'how-to/installation/backup-restore' },
              ],
            },
            {
              label: 'Certificate Management',
              collapsed: true,
              items: [
                { label: 'Upload Certificates to TVS', slug: 'how-to/certificates/upload-to-tvs' },
                { label: 'Generate CAPF Issuer Certificate', slug: 'how-to/certificates/generate-issuer' },
                { label: 'Renew Expiring Certificates', slug: 'how-to/certificates/renew-certificates' },
              ],
            },
            {
              label: 'Phone Configuration',
              collapsed: true,
              items: [
                { label: 'Configure Cisco 7962G', slug: 'how-to/phone/configure-7962g' },
                { label: 'Enroll Phone with LSC', slug: 'how-to/phone/enroll-lsc' },
              ],
            },
            {
              label: 'Troubleshooting',
              collapsed: true,
              items: [
                { label: 'Debug TVS Issues', slug: 'how-to/troubleshooting/debug-tvs' },
                { label: 'Debug CAPF Enrollment', slug: 'how-to/troubleshooting/debug-capf' },
              ],
            },
            {
              label: 'Security',
              collapsed: true,
              items: [
                { label: 'Secure Production Deployments', slug: 'how-to/security/secure-production' },
              ],
            },
          ],
        },
        {
          label: 'Explanation',
          badge: { text: 'Understanding', variant: 'note' },
          items: [
            { label: 'System Architecture', slug: 'architecture/overview' },
            { label: 'Understanding TVS', slug: 'explanation/understanding-tvs' },
            { label: 'Understanding CAPF', slug: 'explanation/understanding-capf' },
            { label: 'Trust Model & ITL Files', slug: 'architecture/configuration-signing' },
            { label: 'API Architecture', slug: 'api/overview' },
          ],
        },
        {
          label: 'Reference',
          badge: { text: 'Info', variant: 'default' },
          collapsed: false,
          items: [
            { label: 'Web Interface', slug: 'reference/web-interface' },
            {
              label: 'API Reference',
              collapsed: true,
              items: [
                { label: 'Security APIs', slug: 'api/security' },
              ],
            },
            {
              label: 'Protocol Specifications',
              collapsed: true,
              items: [
                { label: 'TVS Protocol', slug: 'reference/protocol/tvs' },
                { label: 'CAPF Protocol', slug: 'reference/protocol/capf' },
              ],
            },
          ],
        },
        {
          label: 'Legacy (Deprecated)',
          badge: { text: 'Old', variant: 'caution' },
          collapsed: true,
          items: [
            { label: 'Installation & Setup (Old)', slug: 'installation' },
            { label: 'TVS Protocol (Old)', slug: 'architecture/tvs-protocol' },
            { label: 'CAPF Protocol (Old)', slug: 'architecture/capf-protocol' },
            { label: 'Device Configuration (Old)', slug: 'guides/device-configuration' },
            { label: 'Web Interface (Old)', slug: 'guides/web-interface' },
            { label: 'Best Practices (Old)', slug: 'security/best-practices' },
          ],
        },
      ],
      customCss: ['./src/styles/custom.css'],
    }),
  ],
});
