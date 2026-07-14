import os

from engine_handler.handler import EngineHandler

engine_handler = EngineHandler(
    os.getenv('BINARY_DIR', ""), os.getenv('CONF_FILE', ""))


def before_feature(context, feature):
    context.shared_data = {}
    engine_handler.start()
    context.shared_data['engine_instance'] = engine_handler


def after_feature(context, feature):
    engine_handler.stop()
