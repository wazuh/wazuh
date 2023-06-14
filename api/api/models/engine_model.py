# coding: utf-8

from __future__ import absolute_import

from api.models.base_model_ import Body


class PolicyIntegrationModel(Body):
    """PolicyIntegration model."""
    def __init__(self, policy: str, integration: str):
        self.swagger_types = {
            'policy': str,
            'integration': str
        }

        self.attribute_map = {
            'policy': 'policy',
            'integration': 'integration'
        }

        self._policy = policy
        self._integration = integration

    @property
    def policy(self):
        return self._policy

    @policy.setter
    def policy(self, policy):
        self._policy = policy

    @property
    def integration(self):
        return self._integration

    @integration.setter
    def integration(self, integration):
        self._integration = integration