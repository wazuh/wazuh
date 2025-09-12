import shutil
import os
from pathlib import Path

from engine_handler.handler import EngineHandler

engine_handler = EngineHandler(
    os.getenv('BINARY_DIR', ""), os.getenv('CONF_FILE', ""))

dbs_path = Path(__file__).resolve().parent / "data" / "dbs"


def before_feature(context, feature):
    context.shared_data = {}
    engine_handler.start()
    context.shared_data['engine_instance'] = engine_handler
    dbs_path.mkdir(exist_ok=True)


def after_feature(context, feature):
    engine_handler.stop()

    # Clean up data directory
    shutil.rmtree(dbs_path)
