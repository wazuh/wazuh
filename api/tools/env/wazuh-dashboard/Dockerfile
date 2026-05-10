FROM public.ecr.aws/wazuh-cicd/wazuh/wazuh-dashboard:5.0.0-latest

# ── Overwatch SIEM branding assets ───────────────────────────────────────────
COPY overwatch-icon.svg        /usr/share/wazuh-dashboard/src/core/server/core_app/assets/overwatch-icon.svg
COPY overwatch-logo-light.svg  /usr/share/wazuh-dashboard/src/core/server/core_app/assets/overwatch-logo-light.svg
COPY overwatch-logo-dark.svg   /usr/share/wazuh-dashboard/src/core/server/core_app/assets/overwatch-logo-dark.svg

# ── Patch login page strings in securityDashboards plugin bundle ──────────────
ENV LOGIN_JS=/usr/share/wazuh-dashboard/plugins/securityDashboards/target/public/securityDashboards.plugin.js

RUN echo "Occurrences before patch: $(grep -o 'wazuh\.' $LOGIN_JS | wc -l)" && \
    # Match 'wazuh.' with single quotes
    sed -i "s/'wazuh\.'/'Overwatch SIEM'/g" "$LOGIN_JS" && \
    # Match "wazuh." with double quotes
    sed -i 's/"wazuh\."/"Overwatch SIEM"/g' "$LOGIN_JS" && \
    # Match wazuh. NOT followed by a letter (catches bare/comma/paren contexts)
    sed -i 's/wazuh\.\([^a-zA-Z0-9_\-]\)/Overwatch SIEM\1/g' "$LOGIN_JS" && \
    # Subtitle — plain text and all quote styles
    sed -i 's/The Open Source Security Platform/Unified XDR \& SIEM Protection/g' "$LOGIN_JS" && \
    sed -i "s/'The Open Source Security Platform'/'Unified XDR \& SIEM Protection'/g" "$LOGIN_JS" && \
    sed -i 's/"The Open Source Security Platform"/"Unified XDR \& SIEM Protection"/g' "$LOGIN_JS" && \
    echo "Occurrences after patch: $(grep -o 'wazuh\.' $LOGIN_JS | wc -l)"

# Also patch any i18n translation JSON files in the security plugin
RUN find /usr/share/wazuh-dashboard/plugins/securityDashboards -name "*.json" \
      -exec sed -i \
        -e 's/The Open Source Security Platform/Unified XDR \& SIEM Protection/g' \
        -e 's/wazuh\./Overwatch SIEM/g' \
        {} \; 2>/dev/null || true

# ── Fix asset ownership ───────────────────────────────────────────────────────
RUN chown wazuh-dashboard:wazuh-dashboard \
    /usr/share/wazuh-dashboard/src/core/server/core_app/assets/overwatch-icon.svg \
    /usr/share/wazuh-dashboard/src/core/server/core_app/assets/overwatch-logo-light.svg \
    /usr/share/wazuh-dashboard/src/core/server/core_app/assets/overwatch-logo-dark.svg \
    2>/dev/null || true
