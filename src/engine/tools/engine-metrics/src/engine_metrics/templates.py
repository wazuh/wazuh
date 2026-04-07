"""HTML templates for the metrics dashboard."""

DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Wazuh Engine Metrics Dashboard</title>
    <script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
    <script src="https://cdn.plot.ly/plotly-2.26.0.min.js"></script>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background: #1e1e1e;
            color: #e0e0e0;
        }
        h1 {
            text-align: center;
            color: #00bcd4;
            margin-bottom: 30px;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        .chart-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(600px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        .chart-container {
            background: #2d2d2d;
            border-radius: 8px;
            padding: 15px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        }
        .chart-title {
            font-size: 18px;
            font-weight: bold;
            margin-bottom: 10px;
            color: #00bcd4;
        }
        .status {
            text-align: center;
            padding: 10px;
            background: #2d2d2d;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        .status.connected { color: #4caf50; }
        .status.disconnected { color: #f44336; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Wazuh Engine Metrics Dashboard</h1>
        <div id="status" class="status disconnected">Connecting...</div>

        <div style="
            background: #2d2d2d;
            border: 1px solid #444;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        ">
            <h2 style="color: #00bcd4; margin: 0 0 15px 0;">Global Metrics</h2>
            <div class="chart-grid">
            <div class="chart-container">
                <div class="chart-title">Bytes Received (total per interval)</div>
                <div id="chart-bytes-received"></div>
            </div>
            <div class="chart-container">
                <div class="chart-title">Events Received (total)</div>
                <div id="chart-events-received"></div>
            </div>
            <div class="chart-container">
                <div class="chart-title">Events Processed (total)</div>
                <div id="chart-processed-total"></div>
            </div>
            <div class="chart-container">
                <div class="chart-title">Events Dropped Input (total)</div>
                <div id="chart-dropped-input"></div>
            </div>
            <div class="chart-container">
                <div class="chart-title">EPS - 1 min</div>
                <div id="chart-eps-1m"></div>
            </div>
            <div class="chart-container">
                <div class="chart-title">EPS - 5 min</div>
                <div id="chart-eps-5m"></div>
            </div>
            <div class="chart-container">
                <div class="chart-title">EPS - 30 min</div>
                <div id="chart-eps-30m"></div>
            </div>
            <div class="chart-container">
                <div class="chart-title">Input Queue (router) - Size</div>
                <div id="chart-queue"></div>
            </div>
            <div class="chart-container">
                <div class="chart-title">Input Queue (router) - Usage %</div>
                <div id="chart-queue-percent"></div>
            </div>
            <div class="chart-container">
                <div class="chart-title">Output Queue (indexer) - Size</div>
                <div id="chart-indexer"></div>
            </div>
            <div class="chart-container">
                <div class="chart-title">Output Queue (indexer) - Usage %</div>
                <div id="chart-indexer-percent"></div>
            </div>
            </div>
        </div>

        <div style="
            background: #2d2d2d;
            border: 1px solid #444;
            border-radius: 8px;
            padding: 20px;
            margin-top: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        ">
            <h2 style="color: #00bcd4; margin: 0 0 15px 0;">Per-Space Metrics</h2>
            <div style="margin-bottom: 15px; display: flex; align-items: center; gap: 10px;">
                <label for="space-select" style="font-size: 16px; color: #e0e0e0;">Space:</label>
                <select id="space-select" onchange="switchSpace(this.value)" style="
                    padding: 8px 16px;
                    font-size: 14px;
                    background: #3d3d3d;
                    color: #e0e0e0;
                    border: 1px solid #555;
                    border-radius: 4px;
                    min-width: 200px;
                ">
                    <option value="">-- Select a space --</option>
                </select>
            </div>
            <div id="space-charts" class="chart-grid" style="display: none;">
                <div class="chart-container">
                    <div class="chart-title">Unclassified Events</div>
                    <div id="chart-space-unclassified"></div>
                </div>
                <div class="chart-container">
                    <div class="chart-title">Discarded Events</div>
                    <div id="chart-space-discarded"></div>
                </div>
                <div class="chart-container">
                    <div class="chart-title">Discarded in Pre-filter</div>
                    <div id="chart-space-prefilter"></div>
                </div>
                <div class="chart-container">
                    <div class="chart-title">Discarded in Post-filter</div>
                    <div id="chart-space-postfilter"></div>
                </div>
                <div class="chart-container">
                    <div class="chart-title">Dropped at Output</div>
                    <div id="chart-space-dropped-output"></div>
                </div>
            </div>
        </div>
    </div>

    <script>
        const socket = io();
        const MAX_POINTS = 300;

        const data = {
            'server.bytes.received': {x: [], y: []},
            'server.events.received': {x: [], y: []},
            'router.events.processed': {x: [], y: []},
            'server.events.dropped.input': {x: [], y: []},
            'router.eps.1m': {x: [], y: []},
            'router.eps.5m': {x: [], y: []},
            'router.eps.30m': {x: [], y: []},
            'router.queue.size': {x: [], y: []},
            'router.queue.usage.percent': {x: [], y: []},
            'indexer.queue.size': {x: [], y: []},
            'indexer.queue.usage.percent': {x: [], y: []}
        };

        const allSpaceData = {};
        let selectedSpace = '';
        const knownSpaces = new Set();

        const spaceSuffixes = {
            'events.unclassified': 'chart-space-unclassified',
            'events.discarded': 'chart-space-discarded',
            'events.discarded.prefilter': 'chart-space-prefilter',
            'events.discarded.postfilter': 'chart-space-postfilter',
            'events.dropped.output': 'chart-space-dropped-output'
        };

        const spaceMetricColors = {
            'events.unclassified': '#ab47bc',
            'events.discarded': '#ef5350',
            'events.discarded.prefilter': '#ffa726',
            'events.discarded.postfilter': '#42a5f5',
            'events.dropped.output': '#e91e63'
        };

        const layoutTemplate = {
            paper_bgcolor: '#2d2d2d',
            plot_bgcolor: '#1e1e1e',
            font: { color: '#e0e0e0' },
            xaxis: { gridcolor: '#3d3d3d', title: 'Time', type: 'date' },
            yaxis: { gridcolor: '#3d3d3d', title: 'Value' },
            margin: { t: 20, b: 40, l: 60, r: 20 },
            height: 300
        };

        function initChart(divId, metricName, color, yAxisTitle) {
            const layout = JSON.parse(JSON.stringify(layoutTemplate));
            layout.yaxis.title = yAxisTitle;
            Plotly.newPlot(divId, [{
                x: [], y: [],
                type: 'scatter', mode: 'lines',
                line: { color: color, width: 2 },
                fill: 'tozeroy', fillcolor: color + '33'
            }], layout, {responsive: true});
        }

        initChart('chart-bytes-received', 'server.bytes.received', '#9c27b0', 'Bytes');
        initChart('chart-events-received', 'server.events.received', '#2196f3', 'Events');
        initChart('chart-processed-total', 'router.events.processed', '#8bc34a', 'Events');
        initChart('chart-dropped-input', 'server.events.dropped.input', '#ff5722', 'Events (total)');
        initChart('chart-eps-1m', 'router.eps.1m', '#00bcd4', 'Events/sec');
        initChart('chart-eps-5m', 'router.eps.5m', '#0097a7', 'Events/sec');
        initChart('chart-eps-30m', 'router.eps.30m', '#00838f', 'Events/sec');
        initChart('chart-queue', 'router.queue.size', '#ff9800', 'Queue Size');
        initChart('chart-queue-percent', 'router.queue.usage.percent', '#ffc107', 'Usage %');
        initChart('chart-indexer', 'indexer.queue.size', '#e91e63', 'Queue Size');
        initChart('chart-indexer-percent', 'indexer.queue.usage.percent', '#795548', 'Usage %');

        const metricChartMap = {
            'server.bytes.received': 'chart-bytes-received',
            'server.events.received': 'chart-events-received',
            'router.events.processed': 'chart-processed-total',
            'server.events.dropped.input': 'chart-dropped-input',
            'router.eps.1m': 'chart-eps-1m',
            'router.eps.5m': 'chart-eps-5m',
            'router.eps.30m': 'chart-eps-30m',
            'router.queue.size': 'chart-queue',
            'router.queue.usage.percent': 'chart-queue-percent',
            'indexer.queue.size': 'chart-indexer',
            'indexer.queue.usage.percent': 'chart-indexer-percent'
        };

        for (const [suffix, chartId] of Object.entries(spaceSuffixes)) {
            initChart(chartId, suffix, spaceMetricColors[suffix], 'Events');
        }

        function switchSpace(spaceName) {
            selectedSpace = spaceName;
            const container = document.getElementById('space-charts');
            if (!spaceName) { container.style.display = 'none'; return; }
            container.style.display = 'grid';
            for (const [suffix, chartId] of Object.entries(spaceSuffixes)) {
                const sd = (allSpaceData[spaceName] && allSpaceData[spaceName][suffix])
                    ? allSpaceData[spaceName][suffix] : {x: [], y: []};
                Plotly.update(chartId, { x: [sd.x], y: [sd.y] }, {}, [0]);
            }
        }

        function registerSpace(spaceName) {
            if (knownSpaces.has(spaceName)) return;
            knownSpaces.add(spaceName);
            allSpaceData[spaceName] = {};
            for (const suffix of Object.keys(spaceSuffixes)) {
                allSpaceData[spaceName][suffix] = {x: [], y: []};
            }
            const select = document.getElementById('space-select');
            const opt = document.createElement('option');
            opt.value = spaceName;
            opt.textContent = spaceName;
            select.appendChild(opt);
            if (knownSpaces.size === 1) { select.value = spaceName; switchSpace(spaceName); }
        }

        socket.on('connect', () => {
            document.getElementById('status').textContent = 'Connected';
            document.getElementById('status').className = 'status connected';
        });

        socket.on('disconnect', () => {
            document.getElementById('status').textContent = 'Disconnected';
            document.getElementById('status').className = 'status disconnected';
        });

        socket.on('metrics_update', (metrics) => {
            const now = new Date();
            metrics.forEach(metric => {
                const name = metric.name;
                const chartId = metricChartMap[name];
                if (chartId && data[name]) {
                    data[name].x.push(now);
                    data[name].y.push(metric.value);
                    if (data[name].x.length > MAX_POINTS) { data[name].x.shift(); data[name].y.shift(); }
                    Plotly.update(chartId, { x: [data[name].x], y: [data[name].y] }, {}, [0]);
                    return;
                }
                if (name.startsWith('space.')) {
                    const rest = name.substring(6);
                    const dotIdx = rest.indexOf('.');
                    if (dotIdx === -1) return;
                    const spaceName = rest.substring(0, dotIdx);
                    const suffix = rest.substring(dotIdx + 1);
                    if (!(suffix in spaceSuffixes)) return;
                    registerSpace(spaceName);
                    const sd = allSpaceData[spaceName][suffix];
                    sd.x.push(now);
                    sd.y.push(metric.value);
                    if (sd.x.length > MAX_POINTS) { sd.x.shift(); sd.y.shift(); }
                    if (spaceName === selectedSpace) {
                        const chartId = spaceSuffixes[suffix];
                        Plotly.update(chartId, { x: [sd.x], y: [sd.y] }, {}, [0]);
                    }
                }
            });
        });
    </script>
</body>
</html>
"""
