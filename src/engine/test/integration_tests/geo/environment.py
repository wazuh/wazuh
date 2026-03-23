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
    if dbs_path.exists():
        shutil.rmtree(dbs_path)
    
    # Clean up physical geo database files but keep store metadata
    # This prevents geo databases from being loaded in other tests
    # while preserving the rest of the store (namespaces, etc.)
    env_dir = os.getenv('ENV_DIR', '')
    if env_dir:
        geo_db_path = Path(env_dir) / "geo"
        if geo_db_path.exists():
            shutil.rmtree(geo_db_path)
            print(f"Cleaned up geo databases: {geo_db_path}")
