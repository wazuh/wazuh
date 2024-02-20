from handler_engine_instance import up_down

up_down_engine = up_down.UpDownEngine()

def before_feature(context, feature):
    up_down_engine.send_start_command()

def after_feature(context, feature):
    up_down_engine.send_stop_command()
