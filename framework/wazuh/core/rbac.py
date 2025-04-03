from multiprocessing.managers import SyncManager

from wazuh.core.exception import WazuhResourceNotFound
from wazuh.core.indexer import get_indexer_client
from wazuh.core.indexer.base import IndexerKey
from wazuh.core.indexer.models.rbac import Policy, Role, Rule, User


class RBACManager:
    """Role-based access control information manager."""

    def __init__(self):
        self._manager: SyncManager = SyncManager()
        self._manager.start()

        self._users: dict[str, User] = self._manager.dict()
        self._roles: dict[str, Role] = self._manager.dict()
        self._policies: dict[str, Policy] = self._manager.dict()
        self._rules: dict[str, Rule] = self._manager.dict()

    async def update(self):
        """Retrieve users' data and update the in memory dictionaries."""
        query = {IndexerKey.QUERY: {IndexerKey.MATCH_ALL: {}}}

        async with get_indexer_client() as indexer_client:
            users = await indexer_client.users.search(query=query)
            self._users = {user.id: user for user in users}

            # Reset dictionaries and replace information
            # Data is processed beforehand to avoid repeating the operation when retrieving it
            self._roles.clear()
            self._policies.clear()
            self._rules.clear()

            for user in users:
                for role in user.roles:
                    if role.name not in self._roles:
                        self._roles.update({role.name: role})

                    for policy in role.policies:
                        if policy.name not in self._policies:
                            self._policies.update({policy.name: policy})

                    for rule in role.rules:
                        if rule.name not in self._rules:
                            self._rules.update({rule.name: rule})

    def shutdown(self):
        """Shutdown sync manager."""
        self._manager.shutdown()

    def get_user(self, id: str) -> User:
        """Get a specific user.

        Parameters
        ----------
        id : str
            User identifier.

        Returns
        -------
        User
            User instance.
        """
        if id not in self._users:
            raise WazuhResourceNotFound(4027, extra_message={'entity': 'user', 'entities': 'users'})

        return self._users.get(id)

    def get_user_by_name(self, name: str) -> User:
        """Get a specific user by its name.

        Parameters
        ----------
        name : str
            User name.

        Returns
        -------
        User
            User instance.
        """
        users = self.get_users()
        for user in users:
            if user.name == name:
                return user

        raise WazuhResourceNotFound(4027, extra_message={'entity': 'user', 'entities': 'users'})

    def get_users(self) -> list[User]:
        """Get all users.

        Returns
        -------
        list[User]
            Users list.
        """
        return list(self._users.values())

    def get_role(self, name: str) -> Role:
        """Get a specific role.

        Parameters
        ----------
        name : str
            Role name.

        Returns
        -------
        Role
            Role instance.
        """
        if name not in self._roles:
            raise WazuhResourceNotFound(4027, extra_message={'entity': 'role', 'entities': 'roles'})

        return self._roles.get(name)

    def get_roles(self) -> list[Role]:
        """Get all roles.

        Returns
        -------
        list[Role]
            Roles list.
        """
        return list(self._roles.values())

    def get_policy(self, name: str) -> Policy:
        """Get a specific policy.

        Parameters
        ----------
        name : str
            Policy name.

        Returns
        -------
        Policy
            Policy instance.
        """
        if name not in self._policies:
            raise WazuhResourceNotFound(4027, extra_message={'entity': 'policy', 'entities': 'policies'})

        return self._policies.get(name)

    def get_policies(self) -> list[Policy]:
        """Get all policies.

        Returns
        -------
        list[Policy]
            Policies list.
        """
        return list(self._policies.values())

    def get_rule(self, name: str) -> Rule:
        """Get a specific rule.

        Parameters
        ----------
        name : str
            Rule name.

        Returns
        -------
        Rule
            Rule instance.
        """
        if name not in self._rules:
            raise WazuhResourceNotFound(4027, extra_message={'entity': 'rule', 'entities': 'rules'})

        return self._rules.get(name)

    def get_rules(self) -> list[Rule]:
        """Get all rules.

        Returns
        -------
        list[Rule]
            Rules list.
        """
        return list(self._rules.values())
