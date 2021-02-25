FROM base_integration_test

## Install Wazuh Agent 3.13.2
RUN git clone https://github.com/wazuh/wazuh -b v3.13.2 --depth=1
RUN echo 'USER_LANGUAGE="en"\nUSER_NO_STOP="y"\nUSER_INSTALL_TYPE="agent"\nUSER_DIR="/var/ossec"\nUSER_ENABLE_EMAIL="n"\nUSER_ENABLE_SYSCHECK="y"\nUSER_ENABLE_ROOTCHECK="y"\nUSER_ENABLE_OPENSCAP="y"\nUSER_WHITE_LIST="n"\nUSER_ENABLE_SYSLOG="y"\nUSER_ENABLE_AUTHD="y"\nUSER_AUTO_START="n"' > /wazuh/etc/preloaded-vars.conf
RUN /wazuh/install.sh
