from handler_engine_instance import up_down

up_down_engine = up_down.UpDownEngine()

def before_all(context):
    up_down_engine.send_start_command()

def after_all(context):
    up_down_engine.send_stop_command()
