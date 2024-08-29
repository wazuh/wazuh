import os
import signal
import subprocess
from handler_engine_instance import up_down

up_down_engine = up_down.UpDownEngine()

def before_all(context):
    context.shared_data = {}
    up_down_engine.send_start_command()
    context.shared_data['engine_instance'] = up_down_engine

def after_all(context):
    up_down_engine.send_stop_command()
