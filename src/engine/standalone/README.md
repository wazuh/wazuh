# Wazuh Engine Standalone

## Building the standalone package locally

You can build the Wazuh Engine Standalone package locally using the `generate_package.sh` script:

```bash
cd wazuh/src/engine/standalone
./generate_package.sh -a amd64
```

Available options:
- `-a, --architecture <arch>`: Target architecture [amd64/x86_64/arm64/aarch64]. Default: amd64
- `-d, --debug`: Build with debug flags (without optimizations)
- `-s, --store <path>`: Set destination path for the package. Default: ./output
- `--dont-build-docker`: Use existing docker image instead of building a new one
- `--tag <tag>`: Docker image tag to use. Default: latest
- `-h, --help`: Show help

The script will:
1. Build the required Docker image (or use existing one with `--dont-build-docker`)
2. Compile Wazuh Engine inside the container
3. Generate engine schemas
4. Create the standalone package structure
5. Generate a `.tar.gz` file in the output directory

Example output: `wazuh-engine-5.0.0-linux-amd64.tar.gz`

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
- **data/**: Contains the data files used by the engine in runtime, this directory should
    not be modified manually
    - **data/store**: Contains all the assets in catalog in a format that wazuh-engine can understand (precompiled)
    - **data/kvdb**: Contains the key-value database used by the engine in runtime
    - **data/tzdb**: Contains the time zone database used by the engine
    - **data/mmdb**: Contains the MaxMind GeoIP database files
- **logs**: Contains the `alerts-ecs.json` file, which is configured to be the output in
    the default security policy, this file will be created by the engine if it does not exist.
- **sockets**: Used for engine sockets
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
