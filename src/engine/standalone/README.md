

## How to use the standalone engine


Just run the `run_engine.sh` script in the `standalone_engine` directory to start the engine.

```bash
cd wazuh-engine-standalone
./run_engine.sh
```

**NOTE: Currently the engine requires root privileges to run but will be fixed as soon as possible.**

## Directory structure

The standalone engine will create the following directory structure:

- **bin/**: Contains the engine
    - **bin/lib**: Contains the shared libraries used by the engine
- **default-security-policy/**: Contains the core integration files, including systems decoders and outputs
    used to create the base security policy, they may not exist, this is for information purposes only.
- **data/**: Contains the data files used by the engine in runtime, this directory should
    not be modified manually
    - **data/store**: Contains all the asset in catalog  a format that wazuh-engine can understand (Meaning precompiled)
    - **data/kvdb**: Contains the key-value database used by the engine in runtime
    - **data/tzdb**: Contains the time zone database used by the engine
- **logs**: Contains the `alerts-ecs.json` file, which is configured to be the output in
    the default security policy, this file will be created by the engine if it does not exist.
- **sockets**: user for engine sockets
    - **sockets/engine-api.sock**: Engine HTTP server socket.


## How the security default policy was created

This version is distributed without a default policy. you can create it with the following commands:

```bash
# Clone the intelligence data repository on <DIRECTORY>, checkout `decoders_development` branch and replace download path here:
INTELLIGENCE_DATA_RULESET="<DIRECTORY>/intelligence-data/ruleset/"
# Engine standalone directory: ENGINE_STANDALONE_DIR
ENGINE_STANDALONE_DIR="<DOWNLOAD_DIR>/wazuh-engine-standalone/"
# Load the core decoder and output
engine-catalog --api-socket $ENGINE_STANDALONE_DIR/sockets/engine-api.sock -n system create decoder < $INTELLIGENCE_DATA_RULESET/decoders/wazuh-core/core-wazuh-message.yml
engine-catalog --api-socket $ENGINE_STANDALONE_DIR/sockets/engine-api.sock -n system create output < $INTELLIGENCE_DATA_RULESET/outputs/file-output-integrations.yml
# Create default security policy
engine-policy --api-socket $ENGINE_STANDALONE_DIR/sockets/engine-api.sock create -p policy/wazuh/0
# Add the decoder and output to the default security policy
engine-policy --api-socket $ENGINE_STANDALONE_DIR/sockets/engine-api.sock asset-add -n system decoder/core-wazuh-message/0
engine-policy --api-socket $ENGINE_STANDALONE_DIR/sockets/engine-api.sock asset-add -n system output/file-output-integrations/0
# Set the default parent for the decoder in user and wazuh namespaces
engine-policy --api-socket $ENGINE_STANDALONE_DIR/sockets/engine-api.sock parent-set decoder/core-wazuh-message/0
engine-policy --api-socket $ENGINE_STANDALONE_DIR/sockets/engine-api.sock parent-set -n wazuh decoder/core-wazuh-message/0
```

This security policy has one decoder and one output, all in `system` namespace:
 - **decoder/core-wazuh-message/0**: This decoder is root decoder and will map the current time to the `@timestamp` field in the ECS format.

## Core decoder

The core decoder is a root decoder that maps:
- `@timestamp`: The current time in UTC format.
- `tmp_json`: If `$event.original` is a valid JSON, it will be parsed and stored in this field.

Extract of the core decoder:

```yml
  - map:
      - '@timestamp': get_date()
      - tmp_json: parse_json($event.original)
```
