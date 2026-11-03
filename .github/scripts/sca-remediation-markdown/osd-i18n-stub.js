// Stands in for OpenSearch Dashboards' `@osd/i18n` so markdown-renderer.ts can be transpiled and
// run outside the OSD monorepo. It's only used for the fence rule's "Copy code" button label,
// which markdown-renderer.ts always calls with a fixed `defaultMessage: 'Copy code'` — this stub
// just returns that literal, same as OSD's own non-translated fallback behavior, so the button's
// visible text and aria-label match what the dashboard actually renders.
'use strict';

module.exports = {
  i18n: {
    translate: (_id, options) => (options && options.defaultMessage) || '',
  },
};
