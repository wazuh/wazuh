import time
import json
from collections import defaultdict
from pathlib import Path
from threading import Thread, Lock

from flask import Flask, render_template_string
from flask_socketio import SocketIO

from engine_metrics.defaults import DEFAULT_LOG_DIR, DEFAULT_PORT
from engine_metrics.templates import DASHBOARD_HTML


class MetricsReader:
    """Reads metrics from JSON log file and tracks the latest values."""

    def __init__(self, log_dir: Path):
        self.log_dir = log_dir
        self.metrics = defaultdict(lambda: {'timestamp': 0, 'value': 0.0})
        self.lock = Lock()
        self._last_position = 0
        self._current_file = None

    def get_latest_file(self) -> Path:
        """Find the most recent metrics log file."""
        if not self.log_dir.exists():
            raise FileNotFoundError(f"Log directory not found: {self.log_dir}")

        for subdir in [self.log_dir, self.log_dir / "metrics"]:
            metrics_link = subdir / "metrics.json"
            if metrics_link.exists():
                return metrics_link

        log_files = sorted(self.log_dir.rglob("*.json"))
        if log_files:
            return log_files[-1]

        raise FileNotFoundError(f"No metrics log files found in {self.log_dir}")

    def read_new_lines(self):
        """Read new lines from the log file and update metrics."""
        try:
            current_file = self.get_latest_file()

            if self._current_file != current_file:
                self._current_file = current_file
                self._last_position = 0
                print(f"[Reader] Switching to file: {current_file}")

            with open(current_file, 'r') as f:
                f.seek(self._last_position)
                new_lines = f.readlines()
                self._last_position = f.tell()

            with self.lock:
                for line in new_lines:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        metric = json.loads(line)
                        name = metric.get('name')
                        timestamp = metric.get('timestamp', 0)
                        value = metric.get('value', 0.0)
                        if name:
                            self.metrics[name] = {
                                'timestamp': timestamp,
                                'value': value
                            }
                    except json.JSONDecodeError as e:
                        print(f"[Reader] JSON parse error: {e}")

        except FileNotFoundError as e:
            print(f"[Reader] File not found: {e}")
        except Exception as e:
            print(f"[Reader] Error reading metrics: {e}")

    def get_all_metrics(self):
        """Get all current metric values."""
        with self.lock:
            return [
                {'name': name, 'timestamp': info['timestamp'], 'value': info['value']}
                for name, info in self.metrics.items()
            ]


def run(args):
    log_dir = Path(args['log_dir'])
    port = args['port']

    print(f"Wazuh Engine Metrics Dashboard")
    print(f"  Log directory: {log_dir}")
    print(f"  Port: {port}")
    print()

    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'wazuh-metrics-dashboard'
    socketio = SocketIO(app, cors_allowed_origins="*")

    reader = MetricsReader(log_dir)

    @app.route('/')
    def index():
        return render_template_string(DASHBOARD_HTML)

    def background_reader():
        print("[Background] Metrics reader started")
        while True:
            try:
                reader.read_new_lines()
                metrics = reader.get_all_metrics()
                if metrics:
                    socketio.emit('metrics_update', metrics)
                time.sleep(1)
            except Exception as e:
                print(f"[Background] Error: {e}")
                time.sleep(5)

    reader_thread = Thread(target=background_reader, daemon=True)
    reader_thread.start()

    print(f"Dashboard running at http://localhost:{port}")
    print("Press Ctrl+C to stop")
    print()

    socketio.run(app, host='0.0.0.0', port=port, debug=False)


def configure(subparsers):
    parser = subparsers.add_parser(
        'dashboard',
        help='Start the real-time web metrics dashboard'
    )
    parser.add_argument(
        '--log-dir',
        type=str,
        default=DEFAULT_LOG_DIR,
        dest='log_dir',
        help=f'Path to metrics log directory (default: {DEFAULT_LOG_DIR})'
    )
    parser.add_argument(
        '--port',
        type=int,
        default=DEFAULT_PORT,
        help=f'Port to run the dashboard (default: {DEFAULT_PORT})'
    )
    parser.set_defaults(func=run)
