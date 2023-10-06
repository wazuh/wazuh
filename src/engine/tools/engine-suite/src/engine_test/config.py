DEFAULT_CONFIG_FILE = "/var/ossec/etc/engine-test.conf"

class Config:
    config_file = DEFAULT_CONFIG_FILE

    def get_config_file():
        return Config.config_file

    def set_config_file(value):
        Config.config_file = value
