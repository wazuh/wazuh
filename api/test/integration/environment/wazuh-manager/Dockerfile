ARG TEST_IMAGE=centos:7
FROM $TEST_IMAGE

ARG INSTALL_TYPE=stable
ARG BRANCH=master
ARG PACKAGE_VERSION

ADD install_wazuh_manager.sh /install_wazuh_manager.sh
RUN /install_wazuh_manager.sh $INSTALL_TYPE $BRANCH $PACKAGE_VERSION

ADD entrypoint.sh /scripts/entrypoint.sh
