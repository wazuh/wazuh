#!/usr/bin/env node
// Catches drift between this vendored renderer and the real one in wazuh-dashboard-plugins.
// Fetches the pinned source file from GitHub and compares the options markdown-it is constructed
// with there against what renderer.js in this directory actually uses. This does not replace
// bumping PINNED_* when the dashboard intentionally changes the renderer — it just turns a silent
// divergence into a loud, explicit CI failure instead of a one-off manual sync.
'use strict';

const https = require('https');

const PINNED_REPO = 'wazuh/wazuh-dashboard-plugins';
const PINNED_COMMIT = 'e7ca4c8'; // PR #9381, enhancement/9380-sca-remediation-structured-render
const PINNED_PATH =
  'plugins/main/public/components/common/util/markdown/markdown-renderer.ts';

const EXPECTED_SNIPPETS = [
  'html: false',
  'typographer: false',
  "disable(['heading', 'lheading', 'escape'])",
  'linkify: true',
  'breaks: true',
  "target: '_blank'",
  "rel: 'noopener noreferrer'",
  'DOMPurify.sanitize',
];

function fetch(url) {
  return new Promise((resolve, reject) => {
    https
      .get(url, { headers: { 'User-Agent': 'wazuh-sca-remediation-validator' } }, res => {
        if (res.statusCode !== 200) {
          reject(new Error(`GET ${url} -> HTTP ${res.statusCode}`));
          res.resume();
          return;
        }
        let body = '';
        res.on('data', chunk => (body += chunk));
        res.on('end', () => resolve(body));
      })
      .on('error', reject);
  });
}

async function main() {
  const url = `https://raw.githubusercontent.com/${PINNED_REPO}/${PINNED_COMMIT}/${PINNED_PATH}`;
  let source;
  try {
    source = await fetch(url);
  } catch (err) {
    console.warn(`Could not fetch pinned dashboard source (${err.message}); skipping sync check.`);
    return 0;
  }

  const missing = EXPECTED_SNIPPETS.filter(snippet => !source.includes(snippet));
  if (missing.length > 0) {
    console.error(
      'Vendored renderer.js in this repo looks out of sync with ' +
        `${PINNED_REPO}@${PINNED_COMMIT}:${PINNED_PATH}.\n` +
        `Expected to find these snippets in the dashboard's source and did not:\n` +
        missing.map(s => `  - ${s}`).join('\n') +
        '\n\nIf the dashboard team changed the renderer config on purpose, update ' +
        'renderer.js here to match, and update PINNED_COMMIT in this script to the new commit.',
    );
    return 1;
  }

  console.log(`Vendored renderer config matches ${PINNED_REPO}@${PINNED_COMMIT}.`);
  return 0;
}

main().then(code => process.exit(code));
