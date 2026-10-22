// Fetches a file from a GitHub repo at a given ref via raw.githubusercontent.com. Fails closed:
// throws on a network error or a non-200 response, never returns a partial or stale result.
'use strict';

const https = require('https');

function fetchRaw(repo, ref, path) {
  const url = `https://raw.githubusercontent.com/${repo}/${ref}/${path}`;
  return new Promise((resolve, reject) => {
    https
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
  });
}

module.exports = { fetchRaw };
