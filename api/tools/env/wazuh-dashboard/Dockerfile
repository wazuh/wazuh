FROM public.ecr.aws/wazuh-cicd/wazuh/wazuh-dashboard:5.0.0-latest

# ── Overwatch SIEM branding assets ───────────────────────────────────────────
# Placed in OpenSearch Dashboards' static /ui/ path so the YAML config
# can reference them as /ui/overwatch-*.svg without any external hosting.
COPY overwatch-icon.svg        /usr/share/wazuh-dashboard/src/core/server/core_app/assets/overwatch-icon.svg
COPY overwatch-logo-light.svg  /usr/share/wazuh-dashboard/src/core/server/core_app/assets/overwatch-logo-light.svg
COPY overwatch-logo-dark.svg   /usr/share/wazuh-dashboard/src/core/server/core_app/assets/overwatch-logo-dark.svg
COPY login-overrides.css       /usr/share/wazuh-dashboard/src/core/server/core_app/assets/login-overrides.css

# ── Patch hardcoded login page strings in the security plugin JS bundle ───────
RUN set -e; \
    PLUGIN_DIR=/usr/share/wazuh-dashboard/plugins/securityDashboards; \
    # Replace "The Open Source Security Platform" subtitle
    find "$PLUGIN_DIR" /usr/share/wazuh-dashboard/src \
         -type f -name "*.js" 2>/dev/null \
    | xargs grep -l "Open Source Security Platform" 2>/dev/null \
    | xargs sed -i \
        's/The Open Source Security Platform/Unified XDR \& SIEM Protection/g' \
    || true; \
    # Replace bare "wazuh" brand name used as alt-text / aria-labels on login
    find "$PLUGIN_DIR" /usr/share/wazuh-dashboard/src \
         -type f -name "*.js" 2>/dev/null \
    | xargs grep -l '"wazuh\."' 2>/dev/null \
    | xargs sed -i 's/"wazuh\."/"Overwatch SIEM"/g' \
    || true

# ── Fix asset ownership ───────────────────────────────────────────────────────
RUN chown wazuh-dashboard:wazuh-dashboard \
    /usr/share/wazuh-dashboard/src/core/server/core_app/assets/overwatch-icon.svg \
    /usr/share/wazuh-dashboard/src/core/server/core_app/assets/overwatch-logo-light.svg \
    /usr/share/wazuh-dashboard/src/core/server/core_app/assets/overwatch-logo-dark.svg \
    /usr/share/wazuh-dashboard/src/core/server/core_app/assets/login-overrides.css \
    2>/dev/null || true
