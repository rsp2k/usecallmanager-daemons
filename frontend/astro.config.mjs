// @ts-check
import { defineConfig } from 'astro/config';
import react from '@astrojs/react';
import tailwindcss from '@tailwindcss/vite';
import node from '@astrojs/node';
import icon from 'astro-icon';
import starlight from '@astrojs/starlight';

// https://astro.build/config
export default defineConfig({
  output: 'server',
  telemetry: false,
  integrations: [
    react(),
    icon({
      include: {
        lucide: ['*'],
      },
    }),
    starlight({
      title: 'UseCallManager Docs',
      description: 'Documentation for UseCallManager security services',
      logo: {
        light: './src/assets/logo-light.svg',
        dark: './src/assets/logo-dark.svg',
        replacesTitle: false,
      },
      social: {
        github: 'https://github.com/rsp2k/usecallmanager-daemons',
      },
      sidebar: [
        {
          label: 'Getting Started',
          items: [
            { label: 'Introduction', slug: 'index' },
            { label: 'Installation', slug: 'installation' },
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
      customCss: ['./src/styles/starlight.css'],
    }),
  ],
  vite: {
    plugins: [tailwindcss()],
    server: {
      allowedHosts: ['.l.supported.systems'],
    },
  },
  adapter: node({
    mode: 'standalone',
  }),
});
