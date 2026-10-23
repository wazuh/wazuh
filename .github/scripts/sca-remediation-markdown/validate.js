#!/usr/bin/env node
// Validates that `remediation:` fields in ruleset/sca/**/*.yml render the way the dashboard's
// Markdown renderer actually renders them — ./renderer.js fetches that renderer's real source at
// run time (see dashboard-ref.js) rather than keeping a copy here — instead of relying on
// authors/reviewers eyeballing raw Markdown for the known bug classes (stray `*`/`_` turning into
// unintended emphasis, bare `----` turning into a <hr>, etc).
//
// Usage: node validate.js <file1.yml> [file2.yml ...]
// Exits 1 if any file has a hard-rule violation. Designed to run only against the SCA YAML files
// changed in a PR (see ../../workflows/5_codequality_sca-remediation-markdown.yml), not the whole
// ruleset on every run.
'use strict';

const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');
const { init, renderRemediation, canonicalize, shutdown } = require('./renderer');

function collectRemediationEntries(node, out) {
  if (Array.isArray(node)) {
    for (const item of node) collectRemediationEntries(item, out);
    return;
  }
  if (node && typeof node === 'object') {
    if (typeof node.remediation === 'string' && typeof node.name === 'string') {
      out.push({ id: node.id, name: node.name, remediation: node.remediation });
    }
    for (const key of Object.keys(node)) collectRemediationEntries(node[key], out);
  }
}

function stripTags(html) {
  return html
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function stripMarkdownSyntax(md) {
  return md
    .replace(/```[\s\S]*?```/g, m => m.replace(/```/g, '').trim())
    .replace(/`([^`]*)`/g, '$1')
    .replace(/\*\*([^*]*)\*\*/g, '$1')
    .replace(/^[ \t]*[-*][ \t]+/gm, '')
    .replace(/^[ \t]*\d+\.[ \t]+/gm, '')
    .replace(/\s+/g, ' ')
    .trim();
}

function fenceBalance(md) {
  const matches = md.match(/```/g);
  return (matches ? matches.length : 0) % 2 === 0;
}

// Catches a specific, previously-seen tooling failure: re-running a surgical YAML splice against
// an already-converted (multi-line) value can duplicate it verbatim instead of replacing it. A
// doubled value still renders as syntactically valid Markdown, so no other check here would catch
// it — this looks for "X\nX\n" shaped content directly.
function isExactlyDoubled(md) {
  const body = md.endsWith('\n') ? md.slice(0, -1) : md;
  if (body.length < 40 || body.length % 2 === 0) return false;
  const half = Math.floor(body.length / 2);
  return body[half] === '\n' && body.slice(0, half) === body.slice(half + 1);
}

async function validateEntry(file, entry) {
  const problems = [];
  const warnings = [];
  const label = `${file} [id ${entry.id ?? '?'}] "${entry.name}"`;

  if (!fenceBalance(entry.remediation)) {
    problems.push({ label, rule: 'unbalanced-fence', detail: 'odd number of ``` delimiters in source' });
  }

  if (isExactlyDoubled(entry.remediation)) {
    problems.push({
      label,
      rule: 'duplicated-content',
      detail: 'the entire value appears to be repeated twice back to back — likely a double-applied edit, not real content',
    });
  }

  const { html, sanitized } = await renderRemediation(entry.remediation);

  if (/<em[\s>]/.test(sanitized)) {
    problems.push({
      label,
      rule: 'unintended-emphasis',
      detail: 'rendered output contains <em> — a bare `*` or `_` in the source paired up into italics; wrap the literal character in backticks or a fenced block instead',
    });
  }

  if (/<hr[\s/>]/.test(sanitized)) {
    problems.push({
      label,
      rule: 'unintended-thematic-break',
      detail: 'rendered output contains <hr> — a bare run of 4+ hyphens in the source was parsed as a horizontal rule; wrap it in backticks or a fenced block instead',
    });
  }

  if (canonicalize(html) !== canonicalize(sanitized)) {
    problems.push({
      label,
      rule: 'sanitize-removed-content',
      detail: 'DOMPurify removed or altered an element/attribute present in the rendered HTML — the source likely contains something DOMPurify treats as unsafe markup',
    });
  }

  const renderedText = stripTags(sanitized);
  const expectedText = stripMarkdownSyntax(entry.remediation);
  if (expectedText.length > 0) {
    const ratio = renderedText.length / expectedText.length;
    if (ratio < 0.7) {
      warnings.push({
        label,
        rule: 'possible-content-loss',
        detail: `rendered text is only ${(ratio * 100).toFixed(0)}% of the source's length after stripping Markdown syntax — spot-check for truncation`,
      });
    }
  }

  return { problems, warnings };
}

async function main(argv) {
  const files = argv.slice(2);
  if (files.length === 0) {
    console.log('No SCA YAML files to validate.');
    return 0;
  }

  try {
    await init();
  } catch (err) {
    console.error(`FAIL: could not initialize the dashboard's renderer — ${err.message}`);
    return 1;
  }

  try {
    let totalChecked = 0;
    const allProblems = [];
    const allWarnings = [];

    for (const file of files) {
      const abs = path.resolve(file);
      if (!fs.existsSync(abs)) {
        console.warn(`Skipping ${file}: not found (likely deleted in this PR)`);
        continue;
      }
      let doc;
      try {
        doc = yaml.load(fs.readFileSync(abs, 'utf8'));
      } catch (err) {
        allProblems.push({ label: file, rule: 'yaml-parse-error', detail: err.message });
        continue;
      }
      const entries = [];
      collectRemediationEntries(doc, entries);
      for (const entry of entries) {
        totalChecked += 1;
        const { problems, warnings } = await validateEntry(file, entry);
        allProblems.push(...problems);
        allWarnings.push(...warnings);
      }
    }

    console.log(`Checked ${totalChecked} remediation field(s) across ${files.length} file(s).`);

    if (allWarnings.length > 0) {
      console.log(`\n${allWarnings.length} warning(s) (non-blocking):`);
      for (const w of allWarnings) {
        console.log(`  WARN  ${w.label}\n        [${w.rule}] ${w.detail}`);
      }
    }

    if (allProblems.length > 0) {
      console.log(`\n${allProblems.length} FAILURE(S):`);
      for (const p of allProblems) {
        console.log(`  FAIL  ${p.label}\n        [${p.rule}] ${p.detail}`);
      }
      return 1;
    }

    console.log('\nAll remediation fields render cleanly.');
    return 0;
  } finally {
    // The renderer's child process holds an open IPC channel, which would otherwise keep this
    // process alive indefinitely instead of exiting after the last await above.
    shutdown();
  }
}

main(process.argv).then(
  code => process.exit(code),
  err => {
    console.error(`FAIL: ${err.message}`);
    process.exit(1);
  },
);
