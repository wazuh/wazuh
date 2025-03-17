# Run Tests

## How to run wazuh-engine

### Pre-requisites

1. Install wazuh-server or create the necessary folders (TODO: link to install wazuh-server)
    ```bash
    # Create the necessary folders
    export WHOAMI=$(whoami)
    sudo install -d -m 0750 -o ${WHOAMI} /var/lib/wazuh-server/
    sudo install -d -m 0750 -o ${WHOAMI} /var/lib/wazuh-server/engine/
    sudo install -d -m 0750 -o ${WHOAMI} /run/wazuh-server/
    ```
2. [Build the engine](build-sources.md#build-from-sources)
3. Integration Tests (IT), helper tests (HT) and Health Check require python tools
    ```bash
      cd ${WAZUH_REPO_DIR}
      # Install python tools
      sudo apt-get install python3-pip
      pip install src/engine/tools/api-communication/
      pip install src/engine/test/engine-test-utils/
      pip install src/engine/tools/engine-suite/
      pip install src/engine/test/health_test/engine-health-test/
      # The following is needed for dynamic e2e test with opensearch
      sudo apt-get update
      sudo apt-get install ca-certificates curl
      sudo install -m 0755 -d /etc/apt/keyrings
      sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
      sudo chmod a+r /etc/apt/keyrings/docker.asc
      # Add the repository to Apt sources:
      echo \
        "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
        $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
        sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
      sudo apt-get update
      sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
      pip install docker
    ```

### How to run Engine UT/CT
```bash
cd ${WAZUH_REPO_DIR}/src/engine/build
ctest -j$(nproc)
```

## How to run Engine IT

```bash
# Clean and set up the environment
cd ${WAZUH_REPO_DIR} # Path of the cloned wa repository
rm -rf /tmp/actions
python3 src/engine/test/setupEnvironment.py -e /tmp/actions
engine-it -e /tmp/actions -t src/engine/test/integration_tests/ init
engine-it -e /tmp/actions -t src/engine/test/integration_tests/ run

```

> [!NOTE]
> More details on how to run the tests can be found in python module readme files.
> `src/engine/test/integration_tests/README.md`

## How to run Engine Helper Tests

```bash
# Clean and set up the environment
cd ${WAZUH_REPO_DIR} # Path of the cloned wa repository
rm -rf /tmp/actions
python3 src/engine/test/setupEnvironment.py -e /tmp/actions
# Initial state
engine-helper-test -e /tmp/actions init --mmdb src/engine/test/helper_tests/mmdb/ --conf src/engine/test/helper_tests/configuration_files/config.env
# Validate helper descriptions
engine-helper-test -e /tmp/actions validate --input-dir src/engine/test/helper_tests/helpers_description/
# Generate tests
engine-helper-test -e /tmp/actions generate-tests --input-dir src/engine/test/helper_tests/helpers_description/ -o /tmp/helper_tests/
# Run tests
engine-helper-test -e /tmp/actions run --input-dir /tmp/helper_tests/
# Validate documentation generation
engine-helper-test -e /tmp/actions generate-doc --input-dir src/engine/test/helper_tests/helpers_description/ -o /tmp/helper_docs/
```

> [!NOTE]
> More details on how to run the tests can be found in python module readme files.
> `src/engine/test/helper_tests/README.md`
