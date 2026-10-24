// Fetches a file from a GitHub repo at a given ref via raw.githubusercontent.com. Fails closed:
// throws on a network error, a non-200 response, or a connection that just hangs (no response,
// not even a clean refusal) past REQUEST_TIMEOUT_MS — never returns a partial or stale result, and
// never leaves the CI job to time out an hour later instead of failing fast with a clear reason.
'use strict';

const https = require('https');

const REQUEST_TIMEOUT_MS = 10_000;

function fetchRaw(repo, ref, path) {
  const url = `https://raw.githubusercontent.com/${repo}/${ref}/${path}`;
  return new Promise((resolve, reject) => {
    const req = https
      .get(url, { headers: { 'User-Agent': 'wazuh-sca-remediation-validator' } }, res => {
        if (res.statusCode !== 200) {
          res.resume();
          reject(new Error(`GET ${url} -> HTTP ${res.statusCode}`));
          return;
        }
        let body = '';
        res.on('data', chunk => (body += chunk));
        res.on('end', () => resolve(body));
      })
      .on('error', err => reject(new Error(`GET ${url} -> ${err.message}`)));
    req.setTimeout(REQUEST_TIMEOUT_MS, () => {
      req.destroy(new Error(`GET ${url} -> timed out after ${REQUEST_TIMEOUT_MS}ms`));
    });
  });
}

// Tries each ref in order, returning the first successful fetch (plus which ref it came from, so
// callers can report it). Throws only if every candidate fails, with all their errors attached.
async function fetchRawWithFallback(repo, refs, filePath) {
  const errors = [];
  for (const ref of refs) {
    try {
      const body = await fetchRaw(repo, ref, filePath);
      return { body, ref };
    } catch (err) {
      errors.push(err);
    }
  }
  throw new Error(
    `All ${refs.length} ref(s) failed for ${repo}:${filePath} (tried ${refs.join(', ')}): ` +
      errors.map(e => e.message).join('; '),
  );
}

module.exports = { fetchRaw, fetchRawWithFallback };
