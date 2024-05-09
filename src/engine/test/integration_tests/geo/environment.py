from pathlib import Path
import shutil

from handler_engine_instance import up_down

up_down_engine = up_down.UpDownEngine()
dbs_path = Path(__file__).resolve().parent / "data" / "dbs"


def before_feature(context, feature):
    context.up_down_engine = up_down_engine
    up_down_engine.send_start_command()
    dbs_path.mkdir(exist_ok=True)


def after_feature(context, feature):
    up_down_engine.send_stop_command()

    # Clean up data directory
    shutil.rmtree(dbs_path)
