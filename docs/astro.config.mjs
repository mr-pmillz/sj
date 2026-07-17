import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

const [repositoryOwner, repositoryName] = (
  process.env.GITHUB_REPOSITORY ?? 'BishopFox/sj'
).split('/');
const base = process.env.DOCS_BASE ?? `/${repositoryName}`;

export default defineConfig({
  site:
    process.env.DOCS_SITE ??
    `https://${repositoryOwner.toLowerCase()}.github.io`,
  base,
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
                'commands/audit',
                'commands/automate',
                'commands/brute',
                'commands/convert',
                'commands/endpoints',
                'commands/mcp',
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
