FROM ubuntu:24.04

RUN apt-get update && apt-get install -y locales && rm -rf /var/lib/apt/lists/* \
	&& localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8
ENV LANG en_US.utf8

# Copy and install dashbord (wazuh-dashboard_5.0.0-latest_amd64.deb)
COPY --chown=root:root wazuh-dashboard_5.0.0-latest_amd64.deb /tmp/wazuh-dashboard_5.0.0-latest_amd64.deb
RUN apt-get update && apt-get install -y /tmp/wazuh-dashboard_5.0.0-latest_amd64.deb

# Entry point /usr/share/wazuh-dashboard/bin/opensearch-dashboards -c /etc/wazuh-dashboard/opensearch_dashboards.yml --allow-root

CMD [ "/usr/share/wazuh-dashboard/bin/opensearch-dashboards", "--allow-root", "-c", "/etc/wazuh-dashboard/opensearch_dashboards_custom.yml" ]
