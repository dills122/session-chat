import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from 'parse5';

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const siteRoot = path.resolve(scriptDirectory, '..');
const outputPath = path.join(siteRoot, 'CONTENT_DUMP.md');

const pages = [
  { label: 'Overview', route: '/session-chat/', file: 'index.html' },
  { label: 'Architecture', route: '/session-chat/architecture/', file: 'architecture/index.html' },
  { label: 'Security', route: '/session-chat/security/', file: 'security/index.html' },
  { label: 'Project', route: '/session-chat/project/', file: 'project/index.html' },
];

const blockTags = new Set(['article', 'aside', 'div', 'dl', 'footer', 'header', 'nav', 'ol', 'p', 'section', 'ul']);
const spacedTags = new Set(['button', 'kbd', 'label', 'small', 'span', 'strong']);

function childNodes(node) {
  return Array.isArray(node.childNodes) ? node.childNodes : [];
}

function attribute(node, name) {
  return node.attrs?.find((item) => item.name === name)?.value;
}

function hasClass(node, className) {
  return attribute(node, 'class')?.split(/\s+/u).includes(className) ?? false;
}

function findElement(node, predicate) {
  if (node.tagName && predicate(node)) return node;

  for (const child of childNodes(node)) {
    const match = findElement(child, predicate);
    if (match) return match;
  }

  return undefined;
}

function requireElement(document, predicate, label) {
  const element = findElement(document, predicate);
  if (!element) throw new Error(`Could not extract ${label}`);
  return element;
}

function plainText(node) {
  if (node.nodeName === '#text') return node.value ?? '';
  if (node.nodeName === '#comment' || node.tagName === 'script' || node.tagName === 'style') return '';
  return childNodes(node).map(plainText).join('');
}

function renderChildren(node) {
  let previousTag;

  return childNodes(node)
    .map((child) => {
      const output = renderNode(child, previousTag);
      if (child.tagName) previousTag = child.tagName;
      return output;
    })
    .join('');
}

function renderNode(node, previousTag) {
  if (node.nodeName === '#text') return node.value ?? '';
  if (node.nodeName === '#comment' || node.tagName === 'script' || node.tagName === 'style') return '';

  const tag = node.tagName;
  const contents = renderChildren(node);

  if (tag === 'h1') return `\n# ${contents}\n`;
  if (tag === 'h2') return `\n## ${contents}\n`;
  if (tag === 'h3') return `\n### ${contents}\n`;
  if (tag === 'h4' || tag === 'h5' || tag === 'h6') return `${contents}\n`;
  if (tag === 'li') return `\n- ${contents}\n`;
  if (tag === 'dt') return `\n${contents}`;
  if (tag === 'dd') return previousTag === 'dt' ? ` — ${contents}\n` : `\n${contents}\n`;
  if (tag === 'code') return `\`${contents}\``;
  if (tag === 'br') return '\n';
  if (tag === 'a') return `\n${contents}\n`;
  if (tag && blockTags.has(tag)) return `\n${contents}\n`;
  if (tag && spacedTags.has(tag)) return ` ${contents} `;
  return contents;
}

function textify(element) {
  return renderChildren(element)
    .split('\n')
    .map((line) => line.replace(/[\t ]+/gu, ' ').trim())
    .filter(Boolean)
    .join('\n')
    .replace(/\n{3,}/gu, '\n\n');
}

const renderedPages = await Promise.all(
  pages.map(async (page) => {
    const html = await fs.readFile(path.join(siteRoot, 'dist', page.file), 'utf8');
    const document = parse(html);
    const title = plainText(requireElement(document, (node) => node.tagName === 'title', `${page.label} title`));
    const description = attribute(
      requireElement(
        document,
        (node) => node.tagName === 'meta' && attribute(node, 'name') === 'description',
        `${page.label} description`,
      ),
      'content',
    );
    if (description === undefined) throw new Error(`Could not extract ${page.label} description content`);

    const main = textify(requireElement(document, (node) => node.tagName === 'main', `${page.label} main content`));
    return { ...page, document, title, description, main };
  }),
);

const globalDocument = renderedPages[0].document;
const navigation = textify(
  requireElement(globalDocument, (node) => node.tagName === 'header' && hasClass(node, 'site-header'), 'global navigation'),
);
const footer = textify(
  requireElement(globalDocument, (node) => node.tagName === 'footer' && hasClass(node, 'site-footer'), 'global footer'),
);
const commandPalette = textify(
  requireElement(
    globalDocument,
    (node) => node.tagName === 'dialog' && hasClass(node, 'command-dialog'),
    'command palette',
  ),
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
