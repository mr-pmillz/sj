import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({
  integrations: [
    starlight({
      title: 'sj - Swagger Jacker',
      description: 'CLI tool for auditing exposed Swagger/OpenAPI definition files',
      favicon: '/favicon.png',
      social: [
        {
          icon: 'github',
          label: 'GitHub',
          href: 'https://github.com/mr-pmillz/sj',
        },
      ],
      customCss: ['./src/styles/custom.css'],
      sidebar: [
        {
          label: 'Getting Started',
          items: [
            { slug: 'getting-started/installation' },
            { slug: 'getting-started/quickstart' },
          ],
        },
        {
          label: 'CLI Reference',
          items: [
            { slug: 'commands/global-flags' },
            {
              label: 'Commands',
              collapsed: true,
              items: [
                'commands/automate',
                'commands/brute',
                'commands/convert',
                'commands/endpoints',
                'commands/prepare',
              ],
            },
          ],
        },
        {
          label: 'Development',
          items: [
            { slug: 'development/architecture' },
            { slug: 'development/contributing' },
          ],
        },
      ],
    }),
  ],
});
