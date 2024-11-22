import os
import json
from engine_test.conf.integration import Formats, IntegrationConf

DEFAULT_CONFIG_FILE = "/var/lib/wazuh-server/engine/engine-test.conf"


class ConfigDatabase:
    '''
    Class to Manage the configuration database of the engine-test.

    Provides the configuration file path and the configuration file itself.
    This class handle save, load and update of the configuration file in a json format.
    '''
    config_file = DEFAULT_CONFIG_FILE  # Default config file

    def __init__(self, db_path=DEFAULT_CONFIG_FILE):
        '''
        Constructor for ConfigStore

        Parameters:
        config_file (str): Path to the configuration file
        '''
        self.config_file = db_path
        self._load_db()

    def _load_db(self):
        '''
        Load the configuration file
        '''

        try:
            with open(self._get_config_file(), 'r') as f:
                self.db = json.load(f)
        except json.JSONDecodeError as e:
            raise Exception(
                f"Configuration file is not a valid JSON. Error: {e}")

    def _save_db(self):
        '''
        Save the configuration file
        '''

        try:
            with open(self._get_config_file(), 'w') as f:
                json.dump(self.db, f, indent=2, separators=(',', ': '))
        except PermissionError as e:
            raise Exception(
                f"Error: Cannot write configuration file. Error: {e}")

    def _get_config_file(self):
        '''
        Get the configuration file path
        '''

        # If is default and not exists, create it
        if self.config_file == DEFAULT_CONFIG_FILE and not os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'w') as f:
                    f.write('{}')
                # Set 640 permissions and owner if possible
                os.chmod(self.config_file, 0o640)
                try:
                    import grp
                    # TODO Move to shared module
                    gid = grp.getgrnam("wazuh").gr_gid
                    os.chown(self.config_file, -1, gid)
                except ImportError as e:
                    print(f"Warning: wazuh group cannot be set for {
                          self.config_file}. Error: {e}")
                except KeyError as e:
                    print(f"Warning: wazuh group cannot be set for {
                          self.config_file}. Error: {e}")
            except PermissionError as e:
                raise Exception(
                    f"Cannot create configuration file. Error: {e}")
        # TODO add param to force creation if not exists

        return self.config_file

    def add_integration(self, integration: IntegrationConf):
        '''
        Add an integration to the configuration database.

        Parameters:
        integration (IntegrationConf): Integration configuration to add
        '''

        name, data = integration.dump_as_tuple()

        if name in self.db:
            raise Exception(f"Integration '{name}' already exists.")

        self.db[name] = data

        self._save_db()

    def remove_integration(self, name: str):
        '''
        Remove an integration from the configuration database.

        Parameters:
        name (str): Integration name to remove
        '''

        if name not in self.db:
            raise Exception(f"Integration '{name}' does not exist.")

        del self.db[name]

        self._save_db()

    def get_integration(self, name: str) -> IntegrationConf:
        '''
        Get an integration from the configuration database.

        Parameters:
        name (str): Integration name to get

        Returns:
        IntegrationConf: Integration configuration
        '''

        if name not in self.db:
            raise Exception(f"Integration '{name}' does not exist.")

        data = self.db[name]

        return IntegrationConf.from_tuple(name, data)
