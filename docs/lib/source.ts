import { llms, loader } from 'fumadocs-core/source';
import { lucideIconsPlugin } from 'fumadocs-core/source/lucide-icons';
import { defineDocs } from 'fumadocs-mdx/macro';
import { applyMdxPreset } from 'fumadocs-mdx/config';
import { metaSchema, pageSchema } from 'fumadocs-core/source/schema';
import { docsRoute } from './shared';
import { celGrammar } from './cel-grammar';

const docs = defineDocs({
  dir: 'content/docs',
  docs: {
    schema: pageSchema,
    // Kanagawa: Shiki themes named after Hokusai's Great Wave.
    mdxOptions: applyMdxPreset({
      rehypeCodeOptions: {
        langs: ['json', 'jsonc', 'yaml', 'sh', 'bash', 'powershell', 'go', celGrammar],
        themes: {
          light: 'kanagawa-lotus',
          dark: 'kanagawa-dragon',
        },
      },
    }),
    postprocess: {
      includeProcessedMarkdown: true,
    },
  },
  meta: {
    schema: metaSchema,
  },
});

export const source = loader({
  baseUrl: docsRoute,
  source: docs.toFumadocsSource(),
  plugins: [lucideIconsPlugin()],
});

export const docsLlms = llms(source, {
  renderPage: async (page) => `# ${page.data.title} (${page.url})

${await page.data.getText('processed')}`,
});
