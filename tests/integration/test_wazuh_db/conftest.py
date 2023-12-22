import pytest

from wazuh_testing.utils.agent_groups import create_group, delete_group
from wazuh_testing.utils.db_queries import global_db

@pytest.fixture(scope='function')
def create_groups(test_metadata):
    if 'pre_required_group' in test_metadata:
        groups = test_metadata['pre_required_group'].split(',')

        for group in groups:
            create_group(group)

    yield

    if 'pre_required_group' in test_metadata:
        groups = test_metadata['pre_required_group'].split(',')

        for group in groups:
            delete_group(group)


@pytest.fixture(scope='function')
def pre_insert_agents_into_group():

    global_db.insert_agent_into_group(2)

    yield

    global_db.clean_agents_from_db()
    global_db.clean_groups_from_db()
    global_db.clean_belongs()
