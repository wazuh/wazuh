# coding: utf-8

from __future__ import absolute_import

from flask import json
from six import BytesIO

from api.models.inline_response200 import InlineResponse200  # noqa: E501
from api.models.inline_response2001 import InlineResponse2001  # noqa: E501
from api.models.inline_response2002 import InlineResponse2002  # noqa: E501
from api.test import BaseTestCase


class TestAgentsController(BaseTestCase):
    """AgentsController integration test stubs"""

    def test_delete_agents(self):
        """Test case for delete_agents

        Delete agents
        """
        query_string = [('pretty', true),
                        ('wait_for_complete', true),
                        ('ids', 'ids_example'),
                        ('purge', true),
                        ('status', 'status_example'),
                        ('older_than', 'older_than_example')]
        response = self.client.open(
            '/agents',
            method='DELETE',
            query_string=query_string)
        self.assert200(response,
                       'Response body is : ' + response.data.decode('utf-8'))

    def test_get_all_agents(self):
        """Test case for get_all_agents

        Get all agents
        """
        query_string = [('pretty', true),
                        ('wait_for_complete', true),
                        ('offset', 56),
                        ('limit', 56),
                        ('select', 'select_example'),
                        ('sort', 'sort_example'),
                        ('search', 'search_example'),
                        ('status', 'status_example'),
                        ('q', 'q_example'),
                        ('older_than', 'older_than_example'),
                        ('os_platform', 'os_platform_example'),
                        ('os_version', 'os_version_example'),
                        ('os_name', 'os_name_example'),
                        ('manager', 'manager_example'),
                        ('version', 'version_example'),
                        ('group', 'group_example'),
                        ('node_name', 'node_name_example'),
                        ('name', 'name_example'),
                        ('ip', 'ip_example')]
        response = self.client.open(
            '/agents',
            method='GET',
            query_string=query_string)
        self.assert200(response,
                       'Response body is : ' + response.data.decode('utf-8'))

    def test_restart_all_agents(self):
        """Test case for restart_all_agents

        Restarts all agents
        """
        query_string = [('wait_for_complete', true)]
        response = self.client.open(
            '/agents/restart',
            method='PUT',
            query_string=query_string)
        self.assert200(response,
                       'Response body is : ' + response.data.decode('utf-8'))


if __name__ == '__main__':
    import unittest
    unittest.main()
