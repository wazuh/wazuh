import json
import time
import logging
from pathlib import Path
from threading import Thread

from flask import Flask, render_template_string
from flask_socketio import SocketIO
from google.protobuf.json_format import ParseDict, MessageToDict

from api_communication.client import APIClient
import api_communication.proto.metrics_pb2 as emetrics
import api_communication.proto.engine_pb2 as engine

from engine_metrics.defaults import DEFAULT_SOCKET, DEFAULT_PORT
from engine_metrics.templates import DASHBOARD_HTML

_META_FILE = Path(__file__).parent.parent / 'metrics_meta.json'


def _load_metrics_meta() -> str:
    """Load metrics_meta.json and return it as a compact JSON string for embedding in JS."""
    try:
        raw = json.loads(_META_FILE.read_text())
        # Strip the comment key — it's not valid metadata
        raw.pop('_comment', None)
        return json.dumps(raw, separators=(',', ':'))
    except Exception as exc:
        logging.getLogger(__name__).warning('Could not load metrics_meta.json: %s', exc)
        return '{}'


def poll_metrics(api_socket):
    """Single dump call to the engine API. Returns (dict, error_str)."""
    try:
        client = APIClient(api_socket)
        error, response = client.send_recv(emetrics.Dump_Request())
        if error:
            return None, f'API error: {error}'
        parsed = ParseDict(response, emetrics.Dump_Response())
        if parsed.status == engine.ERROR:
            return None, f'Engine error: {parsed.error}'
        return response, None
    except Exception as exc:
        return None, str(exc)


def run(args):
    api_socket = args['api_socket']
    port = args['port']
    interval = args['interval']

    print('Wazuh Engine Metrics Dashboard')
    print(f'  API socket : {api_socket}')
    print(f'  Port       : {port}')
    print(f'  Interval   : {interval}s')
    print()

    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'wazuh-metrics-dashboard'
    socketio = SocketIO(app, cors_allowed_origins='*', logger=False, engineio_logger=False)
    logging.getLogger('werkzeug').setLevel(logging.ERROR)

    metrics_meta_json = _load_metrics_meta()

    @app.route('/')
    def index():
        return render_template_string(DASHBOARD_HTML, metrics_meta=metrics_meta_json)

    def background_poller():
        print('[Poller] Started')
        while True:
            try:
                data, err = poll_metrics(api_socket)
                if err:
                    print(f'[Poller] {err}')
                    socketio.emit('poll_error', {'message': err})
                else:
                    socketio.emit('metrics_update', data)
            except Exception as exc:
                print(f'[Poller] Unexpected error: {exc}')
            time.sleep(interval)

    Thread(target=background_poller, daemon=True).start()

    print(f'Dashboard running at http://localhost:{port}')
    print('Press Ctrl+C to stop')
    print()
    socketio.run(app, host='0.0.0.0', port=port, debug=False)


def configure(subparsers):
    parser = subparsers.add_parser(
        'dashboard',
        help='Start the real-time web metrics dashboard (polls the engine API)'
    )
    parser.add_argument(
        '-s', '--api-socket',
        type=str,
        default=DEFAULT_SOCKET,
        dest='api_socket',
        help=f'Engine API socket path (default: {DEFAULT_SOCKET})'
    )
    parser.add_argument(
        '--port',
        type=int,
        default=DEFAULT_PORT,
        help=f'Port to run the dashboard (default: {DEFAULT_PORT})'
    )
    parser.add_argument(
        '--interval',
        type=float,
        default=1.0,
        help='Poll interval in seconds (default: 1.0)'
    )
    parser.set_defaults(func=run)
