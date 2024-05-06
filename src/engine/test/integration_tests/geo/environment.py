from pathlib import Path
import shutil

from handler_engine_instance import up_down

up_down_engine = up_down.UpDownEngine()
dbs_path = Path(__file__).resolve().parent / "data" / "dbs"


def before_feature(context, feature):
    context.up_down_engine = up_down_engine
    up_down_engine.send_start_command()


def after_feature(context, feature):
    up_down_engine.send_stop_command()

    # Clean up data directory
    for child in dbs_path.iterdir():
        if child.is_dir():
            shutil.rmtree(child)
        else:
            child.unlink()
