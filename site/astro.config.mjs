import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({
  site: 'https://oseye.github.io',
  base: '/oseye',
  integrations: [
    starlight({
      title: 'OSEye',
      description: 'Open-source EDR/SIEM for Linux',
      logo: {
        src: './src/assets/logo.svg',
      },
      social: {
        github: 'https://github.com/oseye/oseye',
      },
      sidebar: [
        {
          label: 'Getting Started',
          items: [
            { label: 'Installation', slug: 'getting-started/installation' },
            { label: 'Configuration', slug: 'getting-started/configuration' },
            { label: 'Quick Start', slug: 'getting-started/quickstart' },
          ],
        },
        {
          label: 'Deployment',
          items: [
            { label: 'Single Node', slug: 'deployment/single-node' },
            { label: 'Distributed', slug: 'deployment/distributed' },
            { label: 'Docker', slug: 'deployment/docker' },
            { label: 'Kubernetes', slug: 'deployment/kubernetes' },
          ],
        },
        {
          label: 'Guides',
          items: [
            { label: 'Agent Enrollment', slug: 'guides/agent-enrollment' },
            { label: 'Detection Rules', slug: 'guides/detection-rules' },
            { label: 'Dashboard', slug: 'guides/dashboard' },
            { label: 'Response Actions', slug: 'guides/response-actions' },
            { label: 'Plugins', slug: 'guides/plugins' },
          ],
        },
        {
          label: 'Reference',
          items: [
            { label: 'REST API', slug: 'reference/api' },
            { label: 'Agent Config', slug: 'reference/config-agent' },
            { label: 'Server Config', slug: 'reference/config-server' },
            { label: 'Architecture', slug: 'reference/architecture' },
          ],
        },
        {
          label: 'Security',
          items: [
            { label: 'mTLS', slug: 'security/mtls' },
            { label: 'RBAC', slug: 'security/rbac' },
            { label: 'Integrity', slug: 'security/integrity' },
          ],
        },
      ],
    }),
  ],
});
