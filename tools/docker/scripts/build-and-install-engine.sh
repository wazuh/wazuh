#!/usr/bin/env bash

# Force use the specific commit of master to aviod breaking changes in:
# - Python packages
# - Engine configuration


# Clone the Wazuh repository

git clone "https://github.com/wazuh/wazuh.git" ${WAZUH_ROOT}

cd ${ENGINE_SRC}

if [ -n "${ENGINE_COMMIT_ID}" ]; then
    git checkout ${ENGINE_COMMIT_ID}
fi

git submodule update --init --recursive

# Configure the engine
cmake --preset=${ENGINE_PRESET} --no-warn-unused-cli

# Compile only the engine
cmake --build ${ENGINE_BUILD} --target main -j $(nproc)

# Install the engine
ln -s ${ENGINE_BUILD}/main /usr/bin/wazuh-engine

# Install python packages
pip3 install ${ENGINE_SRC}/tools/api-communication
pip3 install ${ENGINE_SRC}/tools/engine-suite
pip3 install ${ENGINE_SRC}/test/engine-test-utils
pip3 install ${ENGINE_SRC}/test/health_test/engine-health-test
pip3 install ${ENGINE_SRC}/test/integration_tests/engine-it
pip3 install ${ENGINE_SRC}/test/helper_tests/engine_helper_test


# Create directories for the engine
echo "Creating directories for the engine"
mkdir -p /var/ossec/etc
mkdir -p /var/ossec/logs/alerts
mkdir -p /var/ossec/queue/sockets
mkdir -p /var/ossec/etc/kvdb/

mkdir -p /var/ossec/engine/store/schema/wazuh-logpar-types
cp $ENGINE_SRC/ruleset/schemas/wazuh-logpar-types.json /var/ossec/engine/store/schema/wazuh-logpar-types/0
mkdir -p /var/ossec/engine/store/schema/wazuh-asset
cp $ENGINE_SRC/ruleset/schemas/wazuh-asset.json /var/ossec/engine/store/schema/wazuh-asset/0
mkdir -p /var/ossec/engine/store/schema/wazuh-policy
cp $ENGINE_SRC/ruleset/schemas/wazuh-policy.json /var/ossec/engine/store/schema/wazuh-policy/0
mkdir -p /var/ossec/engine/store/schema/engine-schema
cp $ENGINE_SRC/ruleset/schemas/engine-schema.json /var/ossec/engine/store/schema/engine-schema/0


# Launch the engine and save the PID
echo "Launching the engine"
wazuh-engine server start &
echo $! > /tmp/engine.pid
# Check for /var/ossec/queue/sockets/engine-api
while [ ! -S /var/ossec/queue/sockets/engine-api ]; do
    sleep 2
done
# Add GeoIP databases
wazuh-engine geo add /var/ossec/etc/GeoLite2-City.mmdb city
wazuh-engine geo add /var/ossec/etc/GeoLite2-ASN.mmdb asn
echo "Stopping the engine"
kill -SIGTERM $(cat /tmp/engine.pid)



# Basic test config
echo "Creating basic test config"
echo "{}" > /var/ossec/etc/engine-test.conf
engine-test add -i windows -f eventchannel
engine-test add -i syslog -f syslog -o /tmp/syslog.log
engine-test add -i remote-syslog -f remote-syslog -o 127.0.0.1
