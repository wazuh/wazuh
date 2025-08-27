from typing import Any

from wazuh.core.engine.base import BaseModule

class KVDBModule(BaseModule):
    """Class to interact with the Engine KVDB module."""

    MODULE = 'KVDB'

    async def create_kv(self, name: str, path: str) -> dict:
        """Create a new key-value database.

        Parameters
        ----------
        name : str
            The name of the database.
        path : str
            The file system path where the database will be stored.

        Returns
        -------
        dict
            The JSON response from the engine.
        """
        return await self.send(
            path='/kvdb/manager/post',
            data={
                'name': name,
                'path': path
            }
        )

    async def get_kv(self, name: str, key: str) -> dict:
        """Retrieve a value from a key-value database.

        Parameters
        ----------
        name : str
            The name of the database.
        key : str
            The key to retrieve the value for.

        Returns
        -------
        dict
            The JSON response from the engine.
        """
        return await self.send(
            path='/kvdb/db/get',
            data={
                'name': name,
                'key': key
            }
        )

    async def get_all_dbs(self, loaded: bool, filter_by_name: str) -> dict:
        """Retrieve all key-value databases, optionally filtered by name and load status.

        Parameters
        ----------
        loaded : bool
            Whether to return only loaded databases.
        filter_by_name : str
            Filter databases by name.

        Returns
        -------
        dict
            The JSON response from the engine.
        """
        return await self.send(
            path='/kvdb/manager/get',
            data={
                'must_be_loaded': loaded,
                'filter_by_name': filter_by_name
            }
        )

    async def update_kv(self, name: str, key: str, value: Any) -> dict:
        """Update or insert a key-value pair in a database.

        Parameters
        ----------
        name : str
            The name of the database.
        key : str
            The key to update or insert.
        value : Any
            The value to associate with the key.

        Returns
        -------
        dict
            The JSON response from the engine.
        """
        return await self.send(
            path='/kvdb/db/put',
            data={
                'name': name,
                'entry': {
                    'key': key,
                    'value': value
                }
            }
        )

    async def delete_kv(self, name: str) -> dict:
        """Delete a key-value database.

        Parameters
        ----------
        name : str
            The name of the database to delete.

        Returns
        -------
        dict
            The JSON response from the engine.
        """
        return await self.send(
            path='/kvdb/manager/delete',
            data={
                'name': name
            }
        )
