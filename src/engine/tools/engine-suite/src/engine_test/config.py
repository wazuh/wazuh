import os
DEFAULT_CONFIG_FILE = "/var/lib/wazuh-server/engine/engine-test.conf"

class Config:
    config_file = DEFAULT_CONFIG_FILE

    def get_config_file():

        # If is default and not exists, create it
        if Config.config_file == DEFAULT_CONFIG_FILE and not os.path.exists(Config.config_file):
            try:
                with open(Config.config_file, 'w') as f:
                    f.write('{}')
                # Set 640 permissions and owner if possible
                os.chmod(Config.config_file, 0o640)
                try:
                    import grp
                    gid = grp.getgrnam("wazuh").gr_gid
                    os.chown(Config.config_file, -1, gid)
                except ImportError as e:
                    print(f"Warning: wazuh group cannot be set for {Config.config_file}. Error: {e}")
                except KeyError as e:
                    print(f"Warning: wazuh group cannot be set for {Config.config_file}. Error: {e}")
            except PermissionError as e:
                print(f"Error: Cannot write to {Config.config_file}. Error: {e}")
                exit(1)


        return Config.config_file

    def set_config_file(value):
        Config.config_file = value
