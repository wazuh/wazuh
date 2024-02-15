cases_yaml_path = '/home/eduardoleon/git/wazuh/tests/integration/test_aws/data/test_cases/basic_test_module/cases_bucket_defaults.yaml'

from copy import deepcopy

import yaml
with open(cases_yaml_path) as f:
    test_cases_data = yaml.safe_load(f)
configuration_parameters = []
configuration_metadata = []
test_cases_ids = []

for test_case in test_cases_data:
    if test_case.get('metadata') is None:
        test_case['metadata'] = deepcopy(test_case['configuration_parameters'])
    configuration_parameters.append(test_case['configuration_parameters'])
    metadata_parameters = {
        'name': test_case['name'], 'description': test_case['description']}
    metadata_parameters.update(test_case['metadata'])
    configuration_metadata.append(metadata_parameters)
    test_cases_ids.append(test_case['name'])

for param, data in zip(configuration_parameters, configuration_metadata):
        print(param)
        print(data)

print(configuration_parameters)
# print(configuration_metadata)
# print(test_cases_ids)