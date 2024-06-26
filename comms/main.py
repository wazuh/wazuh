from argparse import ArgumentParser, Namespace
from fastapi import FastAPI
from gunicorn.app.base import BaseApplication
from typing import Any, Callable, Dict

from api import router
from commands_manager import generate_commands
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import ConsoleSpanExporter
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

trace.set_tracer_provider(TracerProvider())
tracer = trace.get_tracer(__name__)
trace.get_tracer_provider().add_span_processor(
    BatchSpanProcessor(ConsoleSpanExporter())
)

app = FastAPI()
app.include_router(router)

FastAPIInstrumentor.instrument_app(app)


def get_script_arguments() -> Namespace:
    """Get script arguments.

    Returns
    -------
    argparse.Namespace
        Arguments passed to the script.
    """
    parser = ArgumentParser()
    parser.add_argument("--host", type=str, default="0.0.0.0", help="API host.")
    parser.add_argument("-p", "--port", type=int, default=5000, help="API port.")
    parser.add_argument("-a", "--agent_ids", type=str, help="List of agent IDs.")

    return parser.parse_args()

class StandaloneApplication(BaseApplication):
    def __init__(self, app: Callable, options: Dict[str, Any] = None):
        self.options = options or {}
        self.app = app
        super().__init__()

    def load_config(self):
        config = {
            key: value
            for key, value in self.options.items()
            if key in self.cfg.settings and value is not None
        }
        for key, value in config.items():
            self.cfg.set(key.lower(), value)

    def load(self):
        return self.app

if __name__ == "__main__":
    args = get_script_arguments()

    generate_commands(args.agent_ids)

    try:
        options = {
            "bind": f"{args.host}:{args.port}",
            "workers": 4,
            "worker_class": "uvicorn.workers.UvicornWorker",
            "preload_app": True
        }
        StandaloneApplication(app, options).run()
    except Exception as e:
        print(f"Internal error: {e}")
        exit(1)
