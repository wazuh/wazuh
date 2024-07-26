# Engine python suite tools

The `engine-suite` python package contains various scripts to help developing content for the Engine.

## Installation
Requires `python 3.8`, to install navigate where the Wazuh repository folder is located and run:
```
pip install wazuh/src/engine/tools/engine-suite
```
If we want to install for developing and modifying the scripts, install in editable mode and the additional dev packages:
```
pip install -e wazuh/src/engine/tools/engine-suite[dev]
```
**For developing we recommend to install it under a virtual environment.**

Once installed the following scripts are available in the path:
- [engine-schema](src/engine_schema/README.md)
- engine-decoder
- engine-integration
- engine-diff
- engine-clear
- engine-test
