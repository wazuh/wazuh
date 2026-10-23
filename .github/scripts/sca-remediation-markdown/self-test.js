#!/usr/bin/env node
// A small, network-independent-to-reason-about regression test: a fixed corpus of remediation
// snippets exercising the known bug classes (bare `*`/`_`, bare `----`, a leading `#`, backslashes,
// `<PLACEHOLDER>` text, a URL-like token, lists, bold, fenced code), each with the exact sanitized
// HTML this tool produced the last time someone checked it by hand. It still needs network access
// (renderer.js always fetches the live dashboard source — see dashboard-ref.js), but unlike the
// per-field heuristics in validate.js, a mismatch here means the renderer's actual OUTPUT changed,
// not just that it hit one of the known bug shapes. Run this before validate.js so a renderer
// change is caught with a clear diff instead of surfacing as confusing per-field failures.
'use strict';

const { init, renderRemediation, shutdown } = require('./renderer');
const fixtures = require('./fixtures.json');

async function main() {
  await init();

  try {
    let failures = 0;
    for (const fixture of fixtures) {
      const { sanitized } = await renderRemediation(fixture.markdown);
      if (sanitized !== fixture.expectedHtml) {
        failures += 1;
        console.error(`FAIL: ${fixture.name}`);
        console.error(`  expected: ${JSON.stringify(fixture.expectedHtml)}`);
        console.error(`  actual:   ${JSON.stringify(sanitized)}`);
      }
    }

    if (failures > 0) {
      console.error(
        `\n${failures}/${fixtures.length} fixture(s) failed. If this is an intentional upstream ` +
          `renderer change, re-run the generator that produced fixtures.json's expectedHtml values ` +
          `and review the diff before updating them.`,
      );
      return 1;
    }

    console.log(`All ${fixtures.length} fixtures render as expected.`);
    return 0;
  } finally {
    shutdown();
  }
}

main().then(
  code => process.exit(code),
  err => {
    console.error(`FAIL: ${err.message}`);
    process.exit(1);
  },
);
