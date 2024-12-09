import os
from engine_handler.handler import EngineHandler

engine_handler = EngineHandler(
    os.getenv('BINARY_DIR', ""), os.getenv('CONF_FILE', ""))


def before_all(context):
    engine_handler.start()


def after_all(context):
    engine_handler.stop()
