// Vendored from wazuh-dashboard-plugins, so this repo renders `remediation` exactly the way the
// dashboard does. Source: plugins/main/public/components/common/util/markdown/markdown-renderer.ts,
// the `mdWithCopyableCodeBlocks` instance (PR https://github.com/wazuh/wazuh-dashboard-plugins/pull/9381,
// commit e7ca4c8). If the dashboard changes this config, `check-renderer-sync.js` is meant to catch the
// drift — update PINNED_COMMIT there (and this file) together when it does.
'use strict';

const MarkdownIt = require('markdown-it');
const MarkdownItLinkAttributes = require('markdown-it-link-attributes');
const { JSDOM } = require('jsdom');
const createDOMPurify = require('dompurify');

const dom = new JSDOM('');
const DOMPurify = createDOMPurify(dom.window);

const mdWithCopyableCodeBlocks = new MarkdownIt({
  html: false,
  linkify: true,
  breaks: true,
  typographer: false,
}).disable(['heading', 'lheading', 'escape']);

mdWithCopyableCodeBlocks.use(MarkdownItLinkAttributes, {
  attrs: { target: '_blank', rel: 'noopener noreferrer' },
});

function renderRemediation(markdown) {
  const html = mdWithCopyableCodeBlocks.render(markdown || '');
  const sanitized = DOMPurify.sanitize(html);
  return { html, sanitized };
}

// Structural comparison, not string equality: markdown-it and DOMPurify's DOM round-trip
// serialize the same text differently (e.g. `&quot;` vs a literal `"` inside a <code> text node),
// which is not a real difference. This walks both strings as DOM trees and compares tag/attribute/
// text structure, so it only reports true content changes (an element or attribute DOMPurify
// actually removed), not serialization noise.
// Reuses one scratch element (not a fresh JSDOM per call) — across a full-ruleset sweep
// (~11k remediation fields) constructing a new JSDOM window per entry exhausts the heap.
const scratch = dom.window.document.createElement('div');

function canonicalize(htmlStr) {
  scratch.innerHTML = htmlStr;

  function walk(node) {
    if (node.nodeType === 3) return JSON.stringify(node.textContent);
    if (node.nodeType === 1) {
      const attrs = Array.from(node.attributes)
        .map(a => `${a.name}=${a.value}`)
        .sort()
        .join(',');
      const children = Array.from(node.childNodes).map(walk).join('');
      return `<${node.tagName.toLowerCase()} ${attrs}>${children}</${node.tagName.toLowerCase()}>`;
    }
    return '';
  }

  return walk(scratch);
}

module.exports = { renderRemediation, canonicalize };
