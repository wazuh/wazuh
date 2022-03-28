import pytest
import json
from pathlib import Path

#currentBuildDir = Path(__file__).parent
# Opening JSON file
f = open('/home/francorivero/Desktop/Wazuh_repositories/vagrant/wazuh/src/syscheckd/src/db/smokeTests/output/fileTransaction/action_0.json')


with open("testtoolconfig.json", "r") as read_file:
    data = json.load(read_file)

print(data)
# returns JSON object as
# a dictionary
# data = json.load(f)

# Iterating through the json
# list
for i in data['syscheckd']:
    print(i)

# Closing file
f.close()
