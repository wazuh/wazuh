// Runs the dashboard's fetched, transpiled markdown-renderer.ts inside a vm context — in its own
// OS process, with a scrubbed environment (see renderer.js's spawnChild()). vm.createContext() is
// NOT a security boundary by itself: any host-realm function handed into the context (the
// restricted require() below, or the npm modules it legitimately returns) carries a
// `.constructor.constructor` chain back to the realm that CREATED it — a payload that reaches any
// such function (e.g. `someModule.constructor.constructor('return process')()`) gets the real
// global object of whatever process is running this file, regardless of the vm wrapped around it.
// That's why this file is its own child process with nothing sensitive in its environment: the
// worst an escape can do is reach this process's own (already minimal, secret-free) scope, never
// the parent CI job's.
'use strict';

const path = require('path');
const vm = require('vm');

const ALLOWED_REQUIRES = new Set(['markdown-it', 'markdown-it-link-attributes', 'dompurify']);
function restrictedRequire(request) {
  if (ALLOWED_REQUIRES.has(request)) return require(request);
  if (path.resolve(request) === path.join(__dirname, 'osd-i18n-stub.js')) return require(request);
  throw new Error(
    `The fetched dashboard renderer tried to require('${request}'), which isn't on the allowed ` +
      `list — this tool only runs it enough to call renderMarkdown(), not with full require access.`,
  );
}

let renderMarkdown = null;

function handleInit(msg) {
  const mod = { exports: {} };
  const sandbox = {
    module: mod,
    exports: mod.exports,
    require: restrictedRequire,
    __dirname,
    __filename: msg.filename,
    // Restore the ambient Node globals a normal module would see. The old `new Function(...)`
    // approach ran against the real global object and had these; losing them when the sandbox
    // moved to vm.createContext({}) was an unrelated correctness regression, not a security win —
    // this process boundary (not the vm) is the actual isolation, so granting them here costs
    // nothing extra.
    Buffer,
    TextEncoder,
    TextDecoder,
    URL,
    URLSearchParams,
    setTimeout,
    clearTimeout,
    setInterval,
    clearInterval,
    console,
  };
  const context = vm.createContext(sandbox);
  vm.runInContext(msg.code, context, { filename: msg.filename });
  if (typeof mod.exports.renderMarkdown !== 'function') {
    return { ok: false };
  }
  renderMarkdown = mod.exports.renderMarkdown;
  return { ok: true };
}

function handleRender(msg) {
  if (!renderMarkdown) {
    throw new Error('renderer-child: init was never completed successfully');
  }
  // Identity "sanitizer": we want the raw render here. The parent does the real DOMPurify
  // sanitize pass itself, with its own trusted jsdom/dompurify — that step never needs to run
  // inside this sandbox, since it isn't fetched, third-party-controlled code.
  const html = renderMarkdown(msg.markdown || '', { copyableCodeBlocks: true }, h => h);
  return { html };
}

process.on('message', msg => {
  let result, error;
  try {
    if (msg.type === 'init') result = handleInit(msg);
    else if (msg.type === 'render') result = handleRender(msg);
    else throw new Error(`renderer-child: unknown message type '${msg.type}'`);
  } catch (err) {
    error = err.message;
  }
  process.send({ id: msg.id, result, error });
});
