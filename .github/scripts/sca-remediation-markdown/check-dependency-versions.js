#!/usr/bin/env node
// renderer.js runs the dashboard's own renderer source, but with THIS repo's installed copies of
// markdown-it/dompurify/markdown-it-link-attributes — so a version drift between here and the
// dashboard can still change rendering behavior even though the source itself is always current.
// This checks that drift directly, instead of hoping the source-fetch catches everything.
'use strict';

const { fetchRawWithFallback } = require('./fetch-raw');
const { PLUGIN_REPO, PLATFORM_REPO, pluginRefCandidates, platformRefCandidates } = require('./dashboard-ref');

const ours = require('./package.json').dependencies;

// dompurify and markdown-it-link-attributes come from the plugin's own package.json; the plugin
// doesn't pin markdown-it itself, so its effective version is the platform's.
const CHECKS = [
  { name: 'dompurify', repo: PLUGIN_REPO, refs: pluginRefCandidates(), path: 'plugins/main/package.json' },
  {
    name: 'markdown-it-link-attributes',
    repo: PLUGIN_REPO,
    refs: pluginRefCandidates(),
    path: 'plugins/main/package.json',
  },
  { name: 'markdown-it', repo: PLATFORM_REPO, refs: platformRefCandidates(), path: 'package.json' },
];

function extractVersion(packageJsonText, name) {
  const pkg = JSON.parse(packageJsonText);
  return (pkg.dependencies && pkg.dependencies[name]) || (pkg.devDependencies && pkg.devDependencies[name]);
}

function stripCaret(v) {
  return v ? v.replace(/^[\^~]/, '') : v;
}

async function main() {
  const rows = [];
  let hadFetchError = false;

  for (const check of CHECKS) {
    let theirRaw, ref;
    try {
      const result = await fetchRawWithFallback(check.repo, check.refs, check.path);
      ref = result.ref;
      theirRaw = extractVersion(result.body, check.name);
    } catch (err) {
      console.error(`Could not read ${check.name}'s version from ${check.repo}:${check.path} — ${err.message}`);
      hadFetchError = true;
      continue;
    }
    if (!theirRaw) {
      console.error(`${check.name} not found in ${check.repo}@${ref}:${check.path}`);
      hadFetchError = true;
      continue;
    }
    rows.push({ name: check.name, ours: ours[check.name], theirs: theirRaw, ref });
  }

  if (hadFetchError) {
    console.error('\nFailing closed: could not fully verify dependency versions against the dashboard.');
    return 1;
  }

  console.log('package                      | this repo | dashboard         | ref');
  console.log('-----------------------------|-----------|-------------------|----');
  let mismatched = [];
  for (const row of rows) {
    const match = stripCaret(row.ours) === stripCaret(row.theirs);
    console.log(
      `${row.name.padEnd(28)} | ${String(row.ours).padEnd(9)} | ${String(row.theirs).padEnd(17)} | ${row.ref}${match ? '' : '  <-- MISMATCH'}`,
    );
    if (!match) mismatched.push(row);
  }

  if (mismatched.length > 0) {
    console.error(
      `\n${mismatched.length} package(s) out of sync with the dashboard. Bump this repo's ` +
        `package.json to match (then run \`npm install\` to regenerate the lockfile) and re-run.`,
    );
    return 1;
  }

  console.log('\nAll checked dependency versions match the dashboard.');
  return 0;
}

main().then(code => process.exit(code));
