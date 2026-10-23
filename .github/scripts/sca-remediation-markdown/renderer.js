// Renders `remediation` text the way the dashboard actually does — by fetching the dashboard's
// own markdown-renderer.ts at CI time (see dashboard-ref.js) and transpiling it with esbuild,
// instead of keeping a hand-written copy here that can silently drift from the real one. Call
// init() once (it does the network fetch) before using renderRemediation/canonicalize.
'use strict';

const path = require('path');
const esbuild = require('esbuild');
const { JSDOM } = require('jsdom');
const createDOMPurify = require('dompurify');
const { fetchRawWithFallback } = require('./fetch-raw');
const { PLUGIN_REPO, pluginRefCandidates } = require('./dashboard-ref');

const RENDERER_PATH =
  'plugins/main/public/components/common/util/markdown/markdown-renderer.ts';
const OSD_I18N_IMPORT_RE = /from\s+(['"])@osd\/i18n\1/g;

// The fetched file is remote, third-party-controlled source run via new Function() below, not
// require()'d normally — so it never gets the real `require` and can only reach the exact modules
// markdown-renderer.ts is known to need. A require for anything else (fs, child_process, https, a
// different package entirely) throws instead of silently succeeding.
const ALLOWED_REQUIRES = new Set(['markdown-it', 'markdown-it-link-attributes', 'dompurify']);
function restrictedRequire(request) {
  if (ALLOWED_REQUIRES.has(request)) return require(request);
  if (path.resolve(request) === path.join(__dirname, 'osd-i18n-stub.js')) return require(request);
  throw new Error(
    `The fetched dashboard renderer tried to require('${request}'), which isn't on the allowed ` +
      `list — this tool only runs it enough to call renderMarkdown(), not with full require access.`,
  );
}

const dom = new JSDOM('');
const DOMPurify = createDOMPurify(dom.window);
const scratch = dom.window.document.createElement('div');

let renderMarkdown = null;

async function init() {
  if (renderMarkdown) return;

  const candidates = pluginRefCandidates();
  let source, ref;
  try {
    ({ body: source, ref } = await fetchRawWithFallback(PLUGIN_REPO, candidates, RENDERER_PATH));
  } catch (err) {
    throw new Error(
      `Could not fetch the dashboard's renderer from ${PLUGIN_REPO}:${RENDERER_PATH} — ` +
        `refusing to validate against a stale local copy. (${err.message})`,
    );
  }
  console.log(`renderer.js: using ${PLUGIN_REPO}@${ref}`);
  if (!OSD_I18N_IMPORT_RE.test(source)) {
    throw new Error(
      `Fetched markdown-renderer.ts from ${PLUGIN_REPO}@${ref} but it no longer imports ` +
        `'@osd/i18n' the way this tool expects — the stub substitution below needs updating.`,
    );
  }

  const stubPath = path.join(__dirname, 'osd-i18n-stub.js').replace(/\\/g, '/');
  const patched = source.replace(OSD_I18N_IMPORT_RE, (_m, quote) => `from ${quote}${stubPath}${quote}`);

  let code;
  try {
    code = esbuild.transformSync(patched, { loader: 'ts', format: 'cjs', target: 'node22' }).code;
  } catch (err) {
    throw new Error(`Could not transpile the fetched markdown-renderer.ts: ${err.message}`);
  }

  const mod = { exports: {} };
  const moduleFn = new Function('module', 'exports', 'require', '__dirname', '__filename', code);
  moduleFn(mod, mod.exports, restrictedRequire, __dirname, path.join(__dirname, 'markdown-renderer.fetched.js'));

  if (typeof mod.exports.renderMarkdown !== 'function') {
    throw new Error(
      `Fetched markdown-renderer.ts from ${PLUGIN_REPO}@${ref} transpiled, but didn't export a ` +
        `'renderMarkdown' function — its public API may have changed.`,
    );
  }
  renderMarkdown = mod.exports.renderMarkdown;
}

function renderRemediation(markdown) {
  if (!renderMarkdown) {
    throw new Error('renderer.js: init() must be awaited before renderRemediation()');
  }
  // Pass an identity "sanitizer" to get the raw render, then sanitize separately ourselves —
  // renderMarkdown's third argument always runs, so this is how to see the pre-sanitize HTML too
  // (canonicalize() below diffs the two to catch anything DOMPurify actually had to strip).
  const html = renderMarkdown(markdown || '', { copyableCodeBlocks: true }, h => h);
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

module.exports = { init, renderRemediation, canonicalize };
