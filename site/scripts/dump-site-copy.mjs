import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const siteRoot = path.resolve(scriptDirectory, '..');
const outputPath = path.join(siteRoot, 'CONTENT_DUMP.md');

const pages = [
  { label: 'Overview', route: '/session-chat/', file: 'index.html' },
  { label: 'Architecture', route: '/session-chat/architecture/', file: 'architecture/index.html' },
  { label: 'Security', route: '/session-chat/security/', file: 'security/index.html' },
  { label: 'Project', route: '/session-chat/project/', file: 'project/index.html' },
];

const namedEntities = new Map([
  ['amp', '&'],
  ['apos', "'"],
  ['gt', '>'],
  ['lt', '<'],
  ['nbsp', ' '],
  ['quot', '"'],
]);

function decodeEntities(value) {
  return value
    .replace(/&#x([0-9a-f]+);/giu, (_, number) => String.fromCodePoint(Number.parseInt(number, 16)))
    .replace(/&#([0-9]+);/gu, (_, number) => String.fromCodePoint(Number.parseInt(number, 10)))
    .replace(/&([a-z]+);/giu, (entity, name) => namedEntities.get(name.toLowerCase()) ?? entity);
}

function extract(html, pattern, label) {
  const match = html.match(pattern);
  if (!match?.[1]) throw new Error(`Could not extract ${label}`);
  return match[1];
}

function textify(fragment) {
  const text = fragment
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/giu, '')
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/giu, '')
    .replace(/<!--[\s\S]*?-->/gu, '')
    .replace(/<h1\b[^>]*>/giu, '\n# ')
    .replace(/<h2\b[^>]*>/giu, '\n## ')
    .replace(/<h3\b[^>]*>/giu, '\n### ')
    .replace(/<\/h[1-6]>/giu, '\n')
    .replace(/<li\b[^>]*>/giu, '\n- ')
    .replace(/<\/li>/giu, '\n')
    .replace(/<dt\b[^>]*>/giu, '\n')
    .replace(/<\/dt>\s*<dd\b[^>]*>/giu, ' — ')
    .replace(/<\/dd>/giu, '\n')
    .replace(/<code\b[^>]*>/giu, '`')
    .replace(/<\/code>/giu, '`')
    .replace(/<br\s*\/?>/giu, '\n')
    .replace(/<a\b[^>]*>/giu, '\n')
    .replace(/<\/a>/giu, '\n')
    .replace(/<\/(?:article|aside|div|dl|footer|header|nav|ol|p|section|ul)>/giu, '\n')
    .replace(/<(?:article|aside|div|dl|footer|header|nav|ol|p|section|ul)\b[^>]*>/giu, '\n')
    .replace(/<\/?(?:button|kbd|label|small|span|strong)\b[^>]*>/giu, ' ')
    .replace(/<[^>]+>/gu, ' ');

  return decodeEntities(text)
    .split('\n')
    .map((line) => line.replace(/[\t ]+/gu, ' ').trim())
    .filter(Boolean)
    .join('\n')
    .replace(/\n{3,}/gu, '\n\n');
}

const renderedPages = await Promise.all(
  pages.map(async (page) => {
    const html = await fs.readFile(path.join(siteRoot, 'dist', page.file), 'utf8');
    const title = decodeEntities(extract(html, /<title>([\s\S]*?)<\/title>/iu, `${page.label} title`));
    const description = decodeEntities(
      extract(html, /<meta name="description" content="([^"]*)"/iu, `${page.label} description`),
    );
    const main = textify(extract(html, /<main\b[^>]*>([\s\S]*?)<\/main>/iu, `${page.label} main content`));
    return { ...page, html, title, description, main };
  }),
);

const globalHtml = renderedPages[0].html;
const navigation = textify(extract(globalHtml, /<header class="site-header"[^>]*>([\s\S]*?)<\/header>/iu, 'global navigation'));
const footer = textify(extract(globalHtml, /<footer class="site-footer"[^>]*>([\s\S]*?)<\/footer>/iu, 'global footer'));
const commandPalette = textify(
  extract(globalHtml, /<dialog class="command-dialog"[^>]*>([\s\S]*?)<\/dialog>/iu, 'command palette'),
);

const sections = [
  '# Session Chat site copy',
  '',
  'Generated from the production Astro build by `npm run dump:copy`. Edit the Astro source, not this file.',
  '',
  '## Global navigation',
  '',
  navigation,
  '',
  '## Command palette',
  '',
  commandPalette,
  '',
  '## Global footer',
  '',
  footer,
];

for (const page of renderedPages) {
  sections.push(
    '',
    `## Page: ${page.label}`,
    '',
    `Route: \`${page.route}\``,
    '',
    `Page title: ${page.title}`,
    '',
    `Meta description: ${page.description}`,
    '',
    page.main,
  );
}

await fs.writeFile(outputPath, `${sections.join('\n')}\n`);
process.stdout.write(`Wrote ${path.relative(siteRoot, outputPath)}\n`);
