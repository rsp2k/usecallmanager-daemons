// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// https://astro.build/config
export default defineConfig({
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
            { label: 'Installation & Setup', slug: 'installation' },
          ],
        },
        {
          label: 'API Reference',
          items: [
            { label: 'Overview', slug: 'api/overview' },
            { label: 'Security APIs', slug: 'api/security' },
          ],
        },
        {
          label: 'Security',
          items: [
            { label: 'Best Practices', slug: 'security/best-practices' },
          ],
        },
      ],
      customCss: ['./src/styles/custom.css'],
    }),
  ],
});
