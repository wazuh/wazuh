// Renders `remediation` text the way the dashboard actually does — by fetching the dashboard's
// own markdown-renderer.ts at CI time (see dashboard-ref.js) and transpiling it with esbuild,
// instead of keeping a hand-written copy here that can silently drift from the real one. Call
// init() once (it does the network fetch) before using renderRemediation/canonicalize.
//
// The fetched, transpiled code itself runs in renderer-child.js, in its own child process — see
// that file for why vm.createContext() alone isn't a sufficient boundary, and why the actual
// isolation here is the OS process, not the vm. This module owns the trusted side: fetching,
// transpiling, talking to the child over IPC, enforcing a timeout per call, and the DOMPurify
// sanitize + canonicalize steps (neither of which involve running the fetched code, so neither
// needs to happen inside the sandbox).
'use strict';

const path = require('path');
const { fork } = require('child_process');
const esbuild = require('esbuild');
const { JSDOM } = require('jsdom');
const createDOMPurify = require('dompurify');
const { fetchRawWithFallback } = require('./fetch-raw');
const { PLUGIN_REPO, pluginRefCandidates } = require('./dashboard-ref');

const RENDERER_PATH =
  'plugins/main/public/components/common/util/markdown/markdown-renderer.ts';
const OSD_I18N_IMPORT_RE = /from\s+(['"])@osd\/i18n\1/g;
const CHILD_PATH = path.join(__dirname, 'renderer-child.js');
const CALL_TIMEOUT_MS = 10_000;

// Only pass through what a render actually needs (PATH to find node's own runtime bits, a locale/
// timezone) — never whatever CI secrets happen to be in this job's environment. If the vm-sandboxed
// fetched code in renderer-child.js ever escapes the vm (see that file), this is what keeps it from
// reaching anything the CI job's own process can see.
const CHILD_ENV_ALLOWLIST = ['PATH', 'HOME', 'LANG', 'LC_ALL', 'TZ'];

const dom = new JSDOM('');
const DOMPurify = createDOMPurify(dom.window);
const scratch = dom.window.document.createElement('div');

let child = null;
let nextRequestId = 1;
const pending = new Map();
let initPromise = null;

function spawnChild() {
  const env = {};
  for (const key of CHILD_ENV_ALLOWLIST) {
    if (process.env[key] !== undefined) env[key] = process.env[key];
  }
  const c = fork(CHILD_PATH, [], { env, stdio: ['ignore', 'inherit', 'inherit', 'ipc'] });
  c.on('message', msg => {
    const entry = pending.get(msg.id);
    if (!entry) return;
    pending.delete(msg.id);
    clearTimeout(entry.timer);
    if (msg.error) entry.reject(new Error(msg.error));
    else entry.resolve(msg.result);
  });
  c.on('exit', code => {
    const err = new Error(`renderer child process exited unexpectedly (code ${code})`);
    for (const entry of pending.values()) {
      clearTimeout(entry.timer);
      entry.reject(err);
    }
    pending.clear();
    if (child === c) child = null;
  });
  return c;
}

function callChild(message) {
  return new Promise((resolve, reject) => {
    if (!child) {
      reject(new Error('renderer.js: no renderer child process running — call init() first'));
      return;
    }
    const id = nextRequestId++;
    const timer = setTimeout(() => {
      pending.delete(id);
      // A hang here means the fetched code looped or blocked — kill it rather than let it block
      // CI indefinitely. There's no way to interrupt synchronous JS execution in place; killing
      // the process it runs in is the only way to actually stop it.
      const hungChild = child;
      child = null;
      if (hungChild) hungChild.kill();
      reject(new Error(`renderer child process did not respond within ${CALL_TIMEOUT_MS}ms for request ${id} — killed it`));
    }, CALL_TIMEOUT_MS);
    pending.set(id, { resolve, reject, timer });
    child.send({ ...message, id });
  });
}

async function init() {
  if (initPromise) return initPromise;
  initPromise = (async () => {
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

    child = spawnChild();
    const filename = path.join(__dirname, 'markdown-renderer.fetched.js');
    const result = await callChild({ type: 'init', code, filename });
    if (!result || !result.ok) {
      throw new Error(
        `Fetched markdown-renderer.ts from ${PLUGIN_REPO}@${ref} transpiled, but didn't export a ` +
          `'renderMarkdown' function — its public API may have changed.`,
      );
    }
  })();
  return initPromise;
}

async function renderRemediation(markdown) {
  if (!child) {
    throw new Error('renderer.js: init() must be awaited before renderRemediation()');
  }
  // The fetched renderMarkdown() runs in the sandboxed child (see renderer-child.js) and returns
  // the raw, unsanitized HTML. Sanitizing it is OUR trusted code, not the fetched code, so it runs
  // here, not in the child — canonicalize() below diffs the two to catch anything DOMPurify
  // actually had to strip.
  const { html } = await callChild({ type: 'render', markdown: markdown || '' });
  const sanitized = DOMPurify.sanitize(html);
  return { html, sanitized };
}

function shutdown() {
  if (child) {
    child.kill();
    child = null;
  }
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

module.exports = { init, renderRemediation, canonicalize, shutdown };
