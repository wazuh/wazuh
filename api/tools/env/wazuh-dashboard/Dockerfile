FROM public.ecr.aws/wazuh-cicd/wazuh/wazuh-dashboard:5.0.0-latest

# Overwatch SIEM branding assets
# Placed in OpenSearch Dashboards' static /ui/ path so the YAML config
# can reference them as /ui/overwatch-*.svg without any external hosting.
COPY overwatch-icon.svg       /usr/share/wazuh-dashboard/src/core/server/core_app/assets/overwatch-icon.svg
COPY overwatch-logo-light.svg /usr/share/wazuh-dashboard/src/core/server/core_app/assets/overwatch-logo-light.svg
COPY overwatch-logo-dark.svg  /usr/share/wazuh-dashboard/src/core/server/core_app/assets/overwatch-logo-dark.svg

RUN chown wazuh-dashboard:wazuh-dashboard \
    /usr/share/wazuh-dashboard/src/core/server/core_app/assets/overwatch-icon.svg \
    /usr/share/wazuh-dashboard/src/core/server/core_app/assets/overwatch-logo-light.svg \
    /usr/share/wazuh-dashboard/src/core/server/core_app/assets/overwatch-logo-dark.svg 2>/dev/null || true
