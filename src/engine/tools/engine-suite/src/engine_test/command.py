import os
from engine_test.config import Config

class Command:
    def __init__(self):
        pass

    def run(self, args):
        self.set_config_file(args)

    def configure(self, subparsers):
        pass

    def set_config_file(self, args):
        try:
            path = args['config_file']
            Config.set_config_file(path)
        except KeyError as ex:
            print("Config file not found. Error: {}".format(ex))
            exit(1)
