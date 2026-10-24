// Where this tool gets "the dashboard" from — the live source, not a frozen copy.
//
// The primary ref is this repo's own release line (VERSION.json's "version", e.g. "5.0.0"), since
// that's the dashboard branch this repo's content is actually meant to match — not a frozen commit
// that can't see future changes. `main` is a fallback for when the release branch has been archived
// or removed (e.g. after the release ships and the dashboard repo cleans up old release branches),
// not the primary target: pluginRefCandidates()/platformRefCandidates() try the release ref first
// and only fall back to `main` if that one 404s.
//
// DASHBOARD_REF overrides the plugin ref outright (no fallback) for a one-off check against a
// specific branch/commit — set as a workflow_dispatch input in CI, or an env var locally.
'use strict';

const path = require('path');

const PLUGIN_REPO = 'wazuh/wazuh-dashboard-plugins';
const PLATFORM_REPO = 'wazuh/wazuh-dashboard';

function releaseRef() {
  const version = require(path.join(__dirname, '..', '..', '..', 'VERSION.json')).version;
  if (!version) {
    throw new Error("VERSION.json has no 'version' field — can't derive the dashboard ref from it.");
  }
  return version;
}

// Returns the refs to try, in order. An explicit override is the only ref tried — if someone asked
// for a specific branch/commit, silently falling back to something else would defeat the point.
function pluginRefCandidates() {
  if (process.env.DASHBOARD_REF) return [process.env.DASHBOARD_REF];
  return [releaseRef(), 'main'];
}

function platformRefCandidates() {
  if (process.env.DASHBOARD_PLATFORM_REF) return [process.env.DASHBOARD_PLATFORM_REF];
  return [releaseRef(), 'main'];
}

module.exports = { PLUGIN_REPO, PLATFORM_REPO, pluginRefCandidates, platformRefCandidates };
