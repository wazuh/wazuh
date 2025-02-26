## Inventory harvester QA tests

These tests are meant to verify that after a certain operations, the affected indexes contain the required elements or the lack of them.

### Considerations to create new tests

- Each test is stored in a new numbered folder, but it can be under any arbitrary sub-folders that organize the test according to capabilities, topic, or another criteria.
- Each folder contains:
    - An `inputs` folder with all the events to inject. Make sure that they begin with a number that defines the order, and include the word `delta` or `rsync` in the file name when it corresponds. The JSON events don't require that word in the file name.
    - A Readme.md document that briefly explains the test.
    - A `result.json` file that consists in an array of elements. Each element contains the index name and the expected `data` for that index. The `data` array contains one element for each expected indexed document.
    - The `config.json` and `template.json` that the test tool will use for that case.

### Local run

Make sure to have docker enabled.

- Change dir to `src/` and create an update mappings file `echo "{}" > states_update_mappings.json`
- Compile the server
- Run with `python -m pytest -vv wazuh_modules/inventory_harvester/qa/ --log-cli-level=DEBUG`
- You can filter tests using pytest `-k` option
