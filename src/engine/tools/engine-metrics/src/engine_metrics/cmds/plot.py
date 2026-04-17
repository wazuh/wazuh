"""Static plot: reads a metrics log file and serves an HTML report with all data."""

import json
import logging
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask

from engine_metrics.defaults import DEFAULT_LOG_DIR, DEFAULT_PORT

PLOT_HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Wazuh Engine Metrics - Static Report</title>
    <script src="https://cdn.plot.ly/plotly-2.26.0.min.js"></script>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0; padding: 20px;
            background: #1e1e1e; color: #e0e0e0;
        }}
        h1 {{ text-align: center; color: #00bcd4; margin-bottom: 10px; }}
        .subtitle {{ text-align: center; color: #888; margin-bottom: 30px; font-size: 14px; }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        .section {{
            background: #2d2d2d; border: 1px solid #444; border-radius: 8px;
            padding: 20px; margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        }}
        .section h2 {{ color: #00bcd4; margin: 0 0 15px 0; }}
        .chart-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(600px, 1fr));
            gap: 20px;
        }}
        .chart-box {{
            background: #2d2d2d; border-radius: 8px; padding: 15px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.2);
        }}
        .chart-title {{
            font-size: 16px; font-weight: bold; margin-bottom: 8px; color: #00bcd4;
        }}
        .summary {{
            display: flex; gap: 20px; flex-wrap: wrap; margin-bottom: 20px;
        }}
        .summary-card {{
            background: #3d3d3d; border-radius: 6px; padding: 12px 20px;
            flex: 1; min-width: 180px; text-align: center;
        }}
        .summary-card .label {{ font-size: 12px; color: #888; }}
        .summary-card .value {{ font-size: 22px; font-weight: bold; color: #00bcd4; }}
    </style>
</head>
<body>
<div class="container">
    <h1>Wazuh Engine Metrics Report</h1>
    <div class="subtitle">{subtitle}</div>

    <div class="summary">
        <div class="summary-card">
            <div class="label">File</div>
            <div class="value" style="font-size:14px;">{filename}</div>
        </div>
        <div class="summary-card">
            <div class="label">Data Points</div>
            <div class="value">{total_points}</div>
        </div>
        <div class="summary-card">
            <div class="label">Metrics</div>
            <div class="value">{metric_count}</div>
        </div>
        <div class="summary-card">
            <div class="label">Time Range</div>
            <div class="value" style="font-size:14px;">{time_range}</div>
        </div>
    </div>

    {sections}
</div>
</body>
</html>
"""

COLORS = [
    '#00bcd4', '#2196f3', '#8bc34a', '#ff9800', '#e91e63',
    '#9c27b0', '#ff5722', '#795548', '#607d8b', '#ffc107',
    '#ab47bc', '#ef5350', '#42a5f5', '#66bb6a', '#ffa726',
]


def _parse_log_file(filepath):
    """Parse NDJSON metrics log file into {name: [(timestamp_ms, value), ...]}."""
    series = defaultdict(list)
    count = 0
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                name = entry.get('name')
                ts = entry.get('timestamp', 0)
                val = entry.get('value', 0.0)
                if name:
                    series[name].append((ts, val))
                    count += 1
            except json.JSONDecodeError:
                continue
    # Sort each series by timestamp
    for name in series:
        series[name].sort(key=lambda p: p[0])
    return dict(series), count


def _build_chart_div(chart_id, title, timestamps, values, color):
    """Build a single Plotly chart div + inline JS."""
    xs = json.dumps(timestamps)
    ys = json.dumps(values)
    return f"""
    <div class="chart-box">
        <div class="chart-title">{title}</div>
        <div id="{chart_id}"></div>
        <script>
        Plotly.newPlot('{chart_id}', [{{
            x: {xs}, y: {ys},
            type: 'scatter', mode: 'lines',
            line: {{ color: '{color}', width: 2 }},
            fill: 'tozeroy', fillcolor: '{color}33'
        }}], {{
            paper_bgcolor: '#2d2d2d', plot_bgcolor: '#1e1e1e',
            font: {{ color: '#e0e0e0' }},
            xaxis: {{ gridcolor: '#3d3d3d', title: 'Time', type: 'date' }},
            yaxis: {{ gridcolor: '#3d3d3d', title: 'Value' }},
            margin: {{ t: 20, b: 40, l: 60, r: 20 }},
            height: 300
        }}, {{responsive: true}});
        </script>
    </div>"""


def _ts_to_iso(ts_ms):
    """Convert millisecond timestamp to ISO string."""
    return datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')


def run(args):
    log_file = args.get('file')
    log_dir = Path(args.get('log_dir', DEFAULT_LOG_DIR))
    port = args.get('port', DEFAULT_PORT + 1)

    # Resolve input file
    if log_file:
        filepath = Path(log_file)
    else:
        if not log_dir.exists():
            sys.exit(f'Log directory not found: {log_dir}')
        metrics_link = log_dir / 'metrics.json'
        if metrics_link.exists():
            filepath = metrics_link
        else:
            files = sorted(log_dir.rglob('*.json'))
            if not files:
                sys.exit(f'No metrics log files found in {log_dir}')
            filepath = files[-1]

    if not filepath.exists():
        sys.exit(f'File not found: {filepath}')

    print(f'Reading: {filepath}')
    series, total_points = _parse_log_file(filepath)

    if not series:
        sys.exit('No metrics data found in the file.')

    print(f'  {len(series)} metrics, {total_points} data points')

    # Classify: global vs per-space
    global_metrics = {}
    space_metrics = defaultdict(dict)

    for name, points in series.items():
        if name.startswith('space.'):
            rest = name[6:]
            dot = rest.find('.')
            if dot != -1:
                space_name = rest[:dot]
                suffix = rest[dot + 1:]
                space_metrics[space_name][suffix] = points
                continue
        global_metrics[name] = points

    all_ts = [p[0] for pts in series.values() for p in pts]
    min_ts, max_ts = min(all_ts), max(all_ts)
    time_range = f'{_ts_to_iso(min_ts)} → {_ts_to_iso(max_ts)}'

    # Build HTML
    sections = []
    chart_idx = 0

    if global_metrics:
        charts_html = ''
        for name in sorted(global_metrics.keys()):
            points = global_metrics[name]
            timestamps = [datetime.fromtimestamp(p[0] / 1000, tz=timezone.utc).isoformat() for p in points]
            values = [p[1] for p in points]
            color = COLORS[chart_idx % len(COLORS)]
            charts_html += _build_chart_div(f'chart-g-{chart_idx}', name, timestamps, values, color)
            chart_idx += 1
        sections.append(f"""
        <div class="section">
            <h2>Global Metrics</h2>
            <div class="chart-grid">{charts_html}</div>
        </div>""")

    for sname in sorted(space_metrics.keys()):
        suffixes = space_metrics[sname]
        charts_html = ''
        for suffix in sorted(suffixes.keys()):
            points = suffixes[suffix]
            timestamps = [datetime.fromtimestamp(p[0] / 1000, tz=timezone.utc).isoformat() for p in points]
            values = [p[1] for p in points]
            color = COLORS[chart_idx % len(COLORS)]
            charts_html += _build_chart_div(f'chart-s-{chart_idx}', suffix, timestamps, values, color)
            chart_idx += 1
        sections.append(f"""
        <div class="section">
            <h2>Space: {sname}</h2>
            <div class="chart-grid">{charts_html}</div>
        </div>""")

    html = PLOT_HTML_TEMPLATE.format(
        subtitle=f'Generated from {filepath.name}',
        filename=filepath.name,
        total_points=total_points,
        metric_count=len(series),
        time_range=time_range,
        sections='\n'.join(sections)
    )

    # Serve with Flask
    app = Flask(__name__)
    logging.getLogger('werkzeug').setLevel(logging.ERROR)

    @app.route('/')
    def index():
        return html

    print(f'Serving report at http://localhost:{port}')
    print('Press Ctrl+C to stop')
    app.run(host='0.0.0.0', port=port)

    return 0


def configure(subparsers):
    parser = subparsers.add_parser(
        'plot',
        help='Serve a static HTML report from a metrics log file'
    )
    parser.add_argument(
        'file',
        nargs='?',
        default=None,
        help='Path to metrics log file (NDJSON). If omitted, uses latest file in --log-dir'
    )
    parser.add_argument(
        '--log-dir',
        type=str,
        default=DEFAULT_LOG_DIR,
        dest='log_dir',
        help=f'Metrics log directory (default: {DEFAULT_LOG_DIR})'
    )
    parser.add_argument(
        '--port',
        type=int,
        default=DEFAULT_PORT + 1,
        help=f'Port to serve the report (default: {DEFAULT_PORT + 1})'
    )
    parser.set_defaults(func=run)
