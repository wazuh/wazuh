"""HTML template for the engine-metrics live dashboard.

The template receives METRICS_META_JSON injected by dashboard.py — a JSON object mapping
metric names to {category, unit}.  Adding a new metric only requires updating metrics_meta.json.
"""

DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Wazuh Engine Metrics Dashboard</title>
    <script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
    <script src="https://cdn.plot.ly/plotly-2.26.0.min.js"></script>
    <style>
        * { box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0; padding: 20px;
            background: #1e1e1e; color: #e0e0e0;
        }
        h1 { text-align: center; color: #00bcd4; margin-bottom: 6px; }
        .daemon-info { text-align: center; color: #888; font-size: 13px; margin-bottom: 16px; }
        .status {
            text-align: center; padding: 8px; border-radius: 6px;
            margin-bottom: 24px; font-size: 13px;
        }
        .status.connected    { background: #1b3a1b; color: #4caf50; }
        .status.disconnected { background: #3a1b1b; color: #f44336; }
        .status.error        { background: #3a2b1b; color: #ff9800; }
        .section {
            background: #2d2d2d; border: 1px solid #444; border-radius: 8px;
            padding: 20px; margin-bottom: 24px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        }
        .section h2 { color: #00bcd4; margin: 0 0 16px 0; font-size: 16px; }
        .section-empty { color: #555; font-size: 13px; font-style: italic; }
        .chart-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(560px, 1fr));
            gap: 14px;
        }
        .chart-container { background: #252525; border-radius: 6px; padding: 12px; }
        .chart-title {
            font-size: 12px; font-weight: 600; color: #90caf9;
            margin-bottom: 6px; word-break: break-all;
        }
        .type-badge {
            display: inline-block; font-size: 10px; padding: 1px 5px;
            border-radius: 3px; margin-left: 5px; vertical-align: middle;
            font-weight: normal;
        }
        .type-counter  { background: #1a3a1a; color: #66bb6a; }
        .type-gauge_int{ background: #1a2a3a; color: #64b5f6; }
        .type-gauge_dbl{ background: #1a2a3a; color: #42a5f5; }
        .type-pull     { background: #2a2a1a; color: #ffd54f; }
        #main-container { max-width: 1440px; margin: 0 auto; }
    </style>
</head>
<body>
<div id="main-container">
    <h1>Wazuh Engine Metrics</h1>
    <div id="daemon-info" class="daemon-info">Connecting to engine...</div>
    <div id="status" class="status disconnected">Waiting for data</div>

    <!-- Fixed sections for global metrics, always visible -->
    <div id="sec-events" class="section">
        <h2>&#9654; Events</h2>
        <div id="sec-events-grid" class="chart-grid">
            <p class="section-empty">Waiting for event metrics...</p>
        </div>
    </div>

    <div id="sec-bytes" class="section">
        <h2>&#9654; Bytes</h2>
        <div id="sec-bytes-grid" class="chart-grid">
            <p class="section-empty">Waiting for byte metrics...</p>
        </div>
    </div>

    <!-- Per-space sections created dynamically -->
    <div id="sec-spaces"></div>
</div>

<script>
const socket = io();
const MAX_POINTS = 300;

// Injected by the dashboard server from metrics_meta.json.
// Format: { "metric.name": { "category": "events|bytes|...", "unit": "count|bytes|percent|eps|items" } }
const METRICS_META = {{ metrics_meta | safe }};

// chartId → { type, prevValue }
const charts = {};
// chartId → true
const known = {};

const PALETTE = [
    '#00bcd4','#2196f3','#8bc34a','#ff9800','#e91e63',
    '#9c27b0','#ff5722','#ffc107','#26c6da','#ab47bc',
    '#ef5350','#42a5f5','#66bb6a','#ffa726','#bf360c',
    '#80cbc4','#ce93d8','#a5d6a7','#fff59d','#ef9a9a'
];

function nameColor(name) {
    let h = 5381;
    for (let i = 0; i < name.length; i++) h = ((h << 5) + h + name.charCodeAt(i)) & 0x7fffffff;
    return PALETTE[h % PALETTE.length];
}

// Returns the dashboard section for a global metric.
// Uses METRICS_META when available; falls back to name heuristics; defaults to "events".
function metricCategory(name) {
    const meta = METRICS_META[name];
    if (meta && meta.category) return meta.category;
    // fallback heuristics so metrics added before updating the JSON still appear somewhere
    if (name.includes('.bytes')) return 'bytes';
    return 'events';
}

// Maps a unit string (from METRICS_META) to Plotly y-axis config.
const UNIT_AXIS = {
    'bytes':   { title: 'Bytes' },
    'percent': { title: 'Usage %', range: [0, 100] },
    'eps':     { title: 'Events/sec' },
    'items':   { title: 'Items' },
    'count':   { title: 'Delta/poll' },  // most counters
};

function yAxisCfg(name, type) {
    const meta = METRICS_META[name];
    if (meta && meta.unit && UNIT_AXIS[meta.unit]) return UNIT_AXIS[meta.unit];
    // fallback heuristics
    if (name.endsWith('.percent') || name.includes('.usage.percent'))
        return { title: 'Usage %', range: [0, 100] };
    if (name.includes('.bytes'))   return { title: 'Bytes' };
    if (name.includes('.eps'))     return { title: 'Events/sec' };
    if (name.endsWith('.size'))    return { title: 'Items' };
    if (type === 'counter')        return { title: 'Delta/poll' };
    return { title: 'Value' };
}

// Ensures a grid section exists for a given category (creates on-the-fly for unknown categories).
function ensureCategorySection(category) {
    // Built-in sections already in the HTML
    if (category === 'events') return 'sec-events-grid';
    if (category === 'bytes')  return 'sec-bytes-grid';
    // Dynamic section for any other category
    const sectionId = 'sec-cat-' + category.replace(/\\W/g, '_');
    if (!document.getElementById(sectionId)) {
        const label = category.charAt(0).toUpperCase() + category.slice(1);
        const div = document.createElement('div');
        div.className = 'section';
        div.innerHTML = `<h2>&#9654; ${label}</h2>` +
                        `<div id="${sectionId}-grid" class="chart-grid">` +
                        `<p class="section-empty">Waiting for ${category} metrics...</p></div>`;
        document.getElementById('sec-spaces').insertAdjacentElement('beforebegin', div);
        // Register an entry so we know the grid id
    }
    return sectionId + '-grid';
}

function makeId(scope, name) {
    return ('c_' + scope + '_' + name).replace(/\\W/g, '_');
}

// Ensure a space section exists under #sec-spaces
function ensureSpaceSection(spaceName) {
    const sectionId = 'sec-space-' + spaceName.replace(/\\W/g, '_');
    if (!document.getElementById(sectionId)) {
        const div = document.createElement('div');
        div.id = sectionId;
        div.className = 'section';
        div.innerHTML = `<h2>&#9654; Space: ${spaceName}</h2>` +
                        `<div id="${sectionId}-grid" class="chart-grid"></div>`;
        document.getElementById('sec-spaces').appendChild(div);
    }
    return sectionId;
}

function ensureChart(gridId, chartId, metricName, metricType) {
    if (known[chartId]) return;
    known[chartId] = true;

    const grid = document.getElementById(gridId);
    // Remove placeholder text on first real chart
    const placeholder = grid.querySelector('.section-empty');
    if (placeholder) placeholder.remove();

    const box = document.createElement('div');
    box.className = 'chart-container';
    const isCounter = metricType === 'counter';
    const badgeClass = 'type-' + (metricType || 'pull');
    const suffix = isCounter ? ' <em style="font-size:10px;color:#666">(delta)</em>' : '';
    box.innerHTML = `<div class="chart-title">${metricName}${suffix}` +
                    `<span class="type-badge ${badgeClass}">${metricType || 'pull'}</span></div>` +
                    `<div id="${chartId}"></div>`;
    grid.appendChild(box);

    const color = nameColor(metricName);
    const yConf = yAxisCfg(metricName, metricType);

    Plotly.newPlot(chartId, [{
        x: [], y: [],
        type: 'scatter', mode: 'lines',
        line: { color, width: 2 },
        fill: 'tozeroy', fillcolor: color + '28',
        name: metricName
    }], {
        paper_bgcolor: '#252525', plot_bgcolor: '#1a1a1a',
        font: { color: '#e0e0e0', size: 11 },
        xaxis: { gridcolor: '#333', title: '', type: 'date', tickfont: { size: 10 } },
        yaxis: { gridcolor: '#333', title: yConf.title, tickfont: { size: 10 },
                 ...(yConf.range ? { range: yConf.range } : {}) },
        margin: { t: 10, b: 36, l: 56, r: 10 },
        height: 255,
        showlegend: false
    }, { responsive: true, displayModeBar: false });

    charts[chartId] = { type: metricType, prevValue: null };
}

function pushPoint(chartId, ts, rawValue) {
    const c = charts[chartId];
    if (!c) return;
    let value = rawValue;
    if (c.type === 'counter') {
        if (c.prevValue === null) { c.prevValue = rawValue; return; }
        value = Math.max(0, rawValue - c.prevValue);
        c.prevValue = rawValue;
    }
    Plotly.extendTraces(chartId, { x: [[ts]], y: [[value]] }, [0], MAX_POINTS);
}

socket.on('connect', () => {
    document.getElementById('status').textContent = 'Connected — waiting for first poll...';
    document.getElementById('status').className = 'status connected';
});
socket.on('disconnect', () => {
    document.getElementById('status').textContent = 'Disconnected from dashboard server';
    document.getElementById('status').className = 'status disconnected';
});
socket.on('poll_error', (data) => {
    document.getElementById('status').textContent = 'Engine unreachable: ' + data.message;
    document.getElementById('status').className = 'status error';
});

socket.on('metrics_update', (data) => {
    const ts = new Date(data.timestamp || undefined);

    const infoEl = document.getElementById('daemon-info');
    if (data.name && infoEl.dataset.set !== '1') {
        infoEl.textContent = data.name + (data.uptime ? '  ·  up since ' + data.uptime : '');
        infoEl.dataset.set = '1';
    }

    document.getElementById('status').textContent =
        'Live  ·  last update ' + ts.toLocaleTimeString();
    document.getElementById('status').className = 'status connected';

    // Global metrics — section determined by METRICS_META category
    for (const m of (data.global || [])) {
        if (m.enabled === false) continue;
        const gridId = ensureCategorySection(metricCategory(m.name));
        const chartId = makeId('g', m.name);
        ensureChart(gridId, chartId, m.name, m.type);
        pushPoint(chartId, ts, m.value || 0);
    }

    // Per-space metrics
    for (const space of (data.spaces || [])) {
        const sectionId = ensureSpaceSection(space.name);
        const gridId = sectionId + '-grid';
        for (const m of (space.metrics || [])) {
            if (m.enabled === false) continue;
            const chartId = makeId('s_' + space.name, m.name);
            ensureChart(gridId, chartId, m.name, m.type);
            pushPoint(chartId, ts, m.value || 0);
        }
    }
});
</script>
</body>
</html>
"""
