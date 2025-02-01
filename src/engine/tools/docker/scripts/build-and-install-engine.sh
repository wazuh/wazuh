#!/usr/bin/env bash

# Force use the specific commit of master to aviod breaking changes in:
# - Python packages
# - Engine configuration


# Clone the Wazuh repository

git clone "https://github.com/wazuh/wazuh.git" ${WAZUH_ROOT}

cd ${WAZUH_ROOT}
if [ -n "${ENGINE_COMMIT_ID}" ]; then
    git checkout ${ENGINE_COMMIT_ID}
fi

git submodule update --init --recursive

# Install the engine
USER_LANGUAGE="en"                   \
USER_NO_STOP="y"                     \
USER_CA_STORE="/path/to/my_cert.pem" \
DOWNLOAD_CONTENT="y"                 \
./install.sh

# USER_NO_STOP=no USER_LANGUAGE=en ${WAZUH_ROOT}/install.sh


# Install python packages
cd ${ENGINE_SRC}
pip3 install ${ENGINE_SRC}/tools/api-communication
pip3 install ${ENGINE_SRC}/tools/engine-suite
pip3 install ${ENGINE_SRC}/test/engine-test-utils
pip3 install ${ENGINE_SRC}/test/health_test/engine-health-test
pip3 install ${ENGINE_SRC}/test/integration_tests/engine-it
pip3 install ${ENGINE_SRC}/test/helper_tests/engine-helper-test
pip3 install --upgrade requests


# Launch the engine and save the PID
echo "Launching the engine"
WAZUH_CONFIG_SKIP_API=true /usr/share/wazuh-server/bin/wazuh-engine &
echo $! > /tmp/engine.pid
# Check for the socket to be created
while [ ! -S /run/wazuh-server/engine.socket ]; do
    sleep 2
done
# Add GeoIP databases
echo "Adding GeoIP databases"
engine-geo add /tmp/GeoLite2-City.mmdb city
engine-geo add /tmp/GeoLite2-ASN.mmdb asn
# Clean up the ruleset
echo "Cleaning up the ruleset"
engine-router delete default
engine-clear -f
engine-clear -f # Run it twice to make sure it's empty (BUG in the engine-clear script)

echo "Stopping the engine"
kill -SIGTERM $(cat /tmp/engine.pid)
