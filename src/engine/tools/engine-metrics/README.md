# engine-metrics

Real-time metrics dashboard and CLI tools for Wazuh Engine.

## Installation

```bash
pip install -e tools/engine-metrics
```

## Usage

### Dashboard (real-time web UI)

```bash
engine-metrics dashboard --log-dir /var/wazuh-manager/logs/metrics/metrics --port 5000
```

### Dump (one-shot metrics dump via API)

```bash
engine-metrics dump --socket /run/wazuh-server/engine.socket
```

### List (list all registered metric names)

```bash
engine-metrics list --socket /run/wazuh-server/engine.socket
```

### Get (get a single metric value)

```bash
engine-metrics get --socket /run/wazuh-server/engine.socket --name router.events.processed
engine-metrics get --socket /run/wazuh-server/engine.socket --name events.discarded --space wazuh
```

### Enable/Disable

```bash
engine-metrics enable --socket /run/wazuh-server/engine.socket --name router.events.processed --status true
engine-metrics enable --socket /run/wazuh-server/engine.socket --name events.discarded --space wazuh --status false
```
