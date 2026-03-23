import os
from engine_handler.handler import EngineHandler

engine_handler = EngineHandler(
    os.getenv('BINARY_DIR', ""), os.getenv('CONF_FILE', ""))

def before_all(context):
    context.shared_data = {}
    engine_handler.start()
    context.shared_data['engine_instance'] = engine_handler

def after_all(context):
    engine_handler.stop()
