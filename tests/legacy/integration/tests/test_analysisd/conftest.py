import os
import shutil

import pytest

from wazuh_testing.constants.paths.configurations import CUSTOM_RULES_PATH
from wazuh_testing.constants.daemons import WAZUH_UNIX_GROUP, WAZUH_UNIX_USER


@pytest.fixture()
def prepare_custom_rules_file(request, metadata):
    """Configure a syscollector custom rules for testing.
    Restarting wazuh-analysisd is required to apply this changes.
    """
    data_dir = getattr(request.module, 'RULES_SAMPLE_PATH')
    source_rule = os.path.join(data_dir, metadata['rules_file'])
    target_rule = os.path.join(CUSTOM_RULES_PATH, metadata['rules_file'])

    # copy custom rule with specific privileges
    shutil.copy(source_rule, target_rule)
    shutil.chown(target_rule, WAZUH_UNIX_USER, WAZUH_UNIX_GROUP)

    yield

    # remove custom rule
    os.remove(target_rule)
