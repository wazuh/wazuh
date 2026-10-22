// Where this tool gets "the dashboard" from — the live source, not a frozen copy.
//
// PR #9381 (the Markdown remediation renderer) is not merged yet, so its code isn't on
// wazuh-dashboard-plugins' 5.0.0 branch. Once it merges, change DEFAULT_PLUGIN_REF to '5.0.0'
// (or whatever ref this repo's VERSION.json maps to at the time) in the same commit that updates
// this comment — there is no way to detect "has it merged yet" automatically from here.
//
// DASHBOARD_REF overrides the plugin ref for a one-off check against a different branch/commit
// (set as a workflow_dispatch input in CI, or an env var locally).
'use strict';

const DEFAULT_PLUGIN_REF = 'enhancement/9380-sca-remediation-structured-render';
const PLATFORM_REF = process.env.DASHBOARD_PLATFORM_REF || 'main';

const PLUGIN_REPO = 'wazuh/wazuh-dashboard-plugins';
const PLATFORM_REPO = 'wazuh/wazuh-dashboard';

function pluginRef() {
  return process.env.DASHBOARD_REF || DEFAULT_PLUGIN_REF;
}

module.exports = { PLUGIN_REPO, PLATFORM_REPO, pluginRef, PLATFORM_REF };
