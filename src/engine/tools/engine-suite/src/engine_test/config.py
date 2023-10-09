DEFAULT_CONFIG_FOLDER = "/var/ossec/etc/"
DEFAULT_CONFIG_FILE = "engine-test.conf"

class Config:
    config_file = DEFAULT_CONFIG_FOLDER + DEFAULT_CONFIG_FILE

    def get_config_file_name():
        return DEFAULT_CONFIG_FILE

    def get_config_file():
        return Config.config_file

    def set_config_file(value):
        Config.config_file = value
