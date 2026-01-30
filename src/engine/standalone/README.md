# Wazuh Engine Standalone

## Building the standalone package locally

You can build the Wazuh Engine Standalone package locally using the `generate_package.sh` script:

```bash
cd wazuh/src/engine/standalone
./generate_package.sh -a amd64
```

Available options:
- `-a, --architecture <arch>`: Target architecture [amd64/x86_64/arm64/aarch64]. Default: amd64
- `-j, --jobs <number>`: Number of parallel jobs for compilation. Default: 2
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
