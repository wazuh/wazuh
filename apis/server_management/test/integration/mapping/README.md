## API Integration Test Mapping Script
### What is it
This is a script to generate a JSON file with all the API integration test mapping. This JSON file will be used to run the assigned test whenever a file is modified in a PR.

### How to use it
This script has two modes:
- Generate the JSON file
    Run the script without any argument.
    ```
    python3 _test_mapping.py
    ```
    The JSON file will be generated within the same directory as the script as `integration_test_api_endpoints.json`.
    
- Test the mapping
    Run the script with a relative path from the `wazuh` folder to check if a file is mapped.
    ```
    python3 _test_mapping.py framework/wazuh/agent.py
    ```
    If the file is mapped, this will be the output (for `agent.py`):
    ```
    test_agent_GET_endpoints.tavern.yaml
    test_agent_DELETE_endpoints.tavern.yaml
    test_agent_PUT_endpoints.tavern.yaml
    test_agent_POST_endpoints.tavern.yaml
    test_rbac_black_agent_endpoints.tavern.yaml
    test_rbac_white_agent_endpoints.tavern.yaml
    ```
  
    > **NOTE:** Please use a relative path when trying the testing mode. For instance: `/home/wazuh/Desktop/git/wazuh/framework/wazuh/agent.py` -> `framework/wazuh/agent.py`
