# Inventory Harvester QA Tests

These tests verify that after certain operations are performed, the affected indexes in OpenSearch (Wazuh indexer) contain the expected elements or properly exclude unwanted items.

## Creating New Tests

1. **Folder Structure**
   - Test are divided by module, **`fim`**, **`inventory`** and **`wazuh_db`**.
   - Each test resides in a unique numbered folder underscore the test scenario (e.g., `000_delete_agent`) on the corresponding module component.
2. **Folder Contents**
   - **`inputs/`**: Contains all event JSON files to be injected by the test tool.
     - File names should begin with a number indicating the processing order.
     - If the event relates to a delta-based or rsync-based operation, include the corresponding word (`delta`, `rsync`) in the filename for clarity. (The JSON content itself does not require this keyword.)
   - **`result.json`**: An array of objects defining the expected indexes and the exact documents to be present in each index. Each object has:
     ```json
     {
       "index_name": "some_index",
       "data": [
         { "field1": "value1", "field2": "value2" },
         ...
       ]
     }
     ```
   - **`config.json` and `template.json`**: Configuration files used by the `inventory_harvester_testtool` for that specific test.

## Running Tests Locally

1. **Docker Requirements**
   Ensure Docker is running on your system since the tests rely on containerized environments.

2. **Source Directory**
   You must be in the `src/` directory when running these tests.

3. **Python Virtual Environment**
   For better isolation, create and activate a virtual environment, then install the required dependencies:

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r src/wazuh_modules/inventory_harvester/qa/requirements.txt
   ```

4. **Preparation**

   - Create an update mappings file (if needed):
     ```bash
     echo "{}" > states_update_mappings.json
     ```
   - Compile the server:
     ```bash
     make clean-internals && make deps TARGET=server && make TARGET=server DEBUG=1 -j$(nproc)
     ```
   - **AddressSanitizer Notice**: If you compiled with `TESTS=1` and encounter an `AddressSanitizer` error, run:
     ```bash
     export LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libasan.so.8
     ```

5. **Executing the Tests**
   From the `src/` directory, run:
   ```bash
   python -m pytest -vv -rA wazuh_modules/inventory_harvester/qa/ --log-cli-level=DEBUG
   ```

## Running a Single Test

You can target a specific test by adding `-k <keyword>` to the pytest command. For example, to run only the tests in the `fim` folder:

```bash
python -m pytest -vv wazuh_modules/inventory_harvester/qa/ -k fim --log-cli-level=DEBUG
```

> [!TIP]
> You can list all the available tests with `python3 -m pytest -vv --collect-only  wazuh_modules/inventory_harvester/qa/`
