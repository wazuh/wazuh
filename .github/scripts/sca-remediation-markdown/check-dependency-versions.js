#!/usr/bin/env node
// renderer.js runs the dashboard's own renderer source, but with THIS repo's installed copies of
// markdown-it/dompurify/markdown-it-link-attributes — so a version drift between here and the
// dashboard can still change rendering behavior even though the source itself is always current.
// This checks that drift directly, instead of hoping the source-fetch catches everything.
'use strict';

const fs = require('fs');
const path = require('path');
const semver = require('semver');
const { fetchRawWithFallback } = require('./fetch-raw');
const { PLUGIN_REPO, PLATFORM_REPO, pluginRefCandidates, platformRefCandidates } = require('./dashboard-ref');

// The version actually resolved into node_modules, not the declared range in our package.json —
// comparing two declared ranges as strings can't tell you whether they resolve to the same
// installed version, only whether someone happened to write the same range text. Read the
// package.json file directly rather than require()-ing its subpath: some packages (e.g. dompurify)
// restrict subpath access via their "exports" map, which would otherwise throw here.
function installedVersion(name) {
  const pkgPath = path.join(__dirname, 'node_modules', name, 'package.json');
  return JSON.parse(fs.readFileSync(pkgPath, 'utf8')).version;
}

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

async function checkOne(check) {
  const result = await fetchRawWithFallback(check.repo, check.refs, check.path);
  const theirs = extractVersion(result.body, check.name);
  if (!theirs) {
    throw new Error(`${check.name} not found in ${check.repo}@${result.ref}:${check.path}`);
  }
  return { name: check.name, installed: installedVersion(check.name), theirs, ref: result.ref };
}

async function main() {
  const outcomes = await Promise.allSettled(CHECKS.map(checkOne));

  const rows = [];
  let hadFetchError = false;
  outcomes.forEach((outcome, i) => {
    if (outcome.status === 'rejected') {
      console.error(`Could not check ${CHECKS[i].name}: ${outcome.reason.message}`);
      hadFetchError = true;
    } else {
      rows.push(outcome.value);
    }
  });

  if (hadFetchError) {
    console.error('\nFailing closed: could not fully verify dependency versions against the dashboard.');
    return 1;
  }

  console.log('package                      | installed | dashboard range   | ref');
  console.log('-----------------------------|-----------|-------------------|----');
  let mismatched = [];
  for (const row of rows) {
    const range = semver.validRange(row.theirs);
    // satisfies() answers the question that actually matters: does the version we have installed
    // fall within what the dashboard declares? Not whether the two declared ranges are the same
    // text — ^4.0.1 (ours) and 4.0.2 (theirs) are a compatible patch bump, not a mismatch, and two
    // identical-looking ranges can still resolve to different installed versions over time.
    const match = range ? semver.satisfies(row.installed, range) : false;
    const flag = match ? '' : range ? '  <-- MISMATCH' : '  <-- UNPARSEABLE RANGE';
    console.log(
      `${row.name.padEnd(28)} | ${String(row.installed).padEnd(9)} | ${String(row.theirs).padEnd(17)} | ${row.ref}${flag}`,
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
