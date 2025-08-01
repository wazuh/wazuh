#!/usr/bin/env /var/ossec/framework/python/bin/python3

import json
import time
import sys
import os
import requests
import logging

CONFIG_FILE = "/var/ossec/etc/alert_forwarder.conf"
LOG_PATH = "/var/ossec/logs/ossec.log"

# --- Logging setup ---
logging.basicConfig(
    filename=LOG_PATH,
    level=logging.DEBUG,
    format="%(asctime)s wazuh-forwarder: %(levelname)s: %(message)s",
    datefmt="%Y/%m/%d %H:%M:%S"
)

def log(message, level="INFO"):
    if level == "DEBUG":
        logging.debug(message)
    elif level == "WARNING":
        logging.warning(message)
    elif level == "ERROR":
        logging.error(message)
    else:
        logging.info(message)

def load_config():
    """
    Load configuration from file, applying default values for missing keys.

    Returns:
        dict: Configuration dictionary with required keys and defaults.
    """
    defaults = {
        "ALERTS_FILE": "/var/ossec/logs/alerts/alerts.json",
        "INDEXER_IP": "127.0.0.1",
        "INDEX_NAME": "wazuh-alerts",
        "CERT_FILE": "/etc/wazuh-indexer/certs/admin.pem",
        "KEY_FILE": "/etc/wazuh-indexer/certs/admin-key.pem",
        "CA_CERT": "/etc/wazuh-indexer/certs/root-ca.pem"
    }

    config = defaults.copy()

    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    config[key.strip()] = value.strip()
    else:
        raise FileNotFoundError(f"Configuration file not found: {CONFIG_FILE}")

    # Log which values are being used
    for k in defaults:
        log(f"Config {k} = {config[k]}", "DEBUG")

    return config

def daemonize():
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as e:
        log(f"Fork #1 failed: {e}", "ERROR")
        sys.exit(1)

    os.chdir("/")
    os.setsid()
    os.umask(0)

    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as e:
        log(f"Fork #2 failed: {e}", "ERROR")
        sys.exit(1)

    # Redirect stdout and stderr to log file
    sys.stdout.flush()
    sys.stderr.flush()
    with open(LOG_PATH, 'ab', buffering=0) as log_file:
        os.dup2(log_file.fileno(), sys.stdout.fileno())
        os.dup2(log_file.fileno(), sys.stderr.fileno())

    with open('/dev/null', 'rb', 0) as devnull:
        os.dup2(devnull.fileno(), sys.stdin.fileno())


def is_indexer_ready(config):
    try:
        response = requests.get(
            f"https://{config['INDEXER_IP']}:9200/_cluster/health",
            cert=(config["CERT_FILE"], config["KEY_FILE"]),
            verify=config["CA_CERT"],
            timeout=3
        )
        response.raise_for_status()
        status = response.json().get("status")
        log(f"Indexer health: {status}")
        return status in ("green", "yellow")
    except Exception as e:
        log(f"Indexer health check failed: {e}", "ERROR")
        return False


class AlertForwarder:
    def __init__(self, config):
        self.config = config

    def send_alert(self, alert):
        try:
            response = requests.post(
                f"https://{self.config['INDEXER_IP']}:9200/{self.config['INDEX_NAME']}/_doc",
                json=alert,
                cert=(self.config["CERT_FILE"], self.config["KEY_FILE"]),
                verify=self.config["CA_CERT"],
                timeout=3
            )
            response.raise_for_status()
        except requests.RequestException as e:
            try:
                error_detail = response.json()
                log(f"Failed to send alert: {e} | Details: {json.dumps(error_detail)}", "ERROR")
            except Exception:
                log(f"Failed to send alert: {e}", "ERROR")

    def run(self):
        alert_file = self.config["ALERTS_FILE"]
        last_inode = None
        f = None

        while True:
            try:
                if not os.path.exists(alert_file):
                    time.sleep(1)
                    continue

                current_inode = os.stat(alert_file).st_ino
                if f is None or last_inode != current_inode:
                    if f:
                        f.close()
                    f = open(alert_file, "r")
                    f.seek(0, os.SEEK_END)
                    last_inode = current_inode
                    log(f"Reopened alert file (inode changed): {alert_file}")
                else:
                    if f.tell() > os.stat(alert_file).st_size:
                        log("File truncated. Rewinding.")
                        f.seek(0)

                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue

                line = line.strip()
                if not line:
                    continue

                try:
                    alert = json.loads(line)
                    self.send_alert(alert)
                except json.JSONDecodeError:
                    log("Malformed JSON in alert.", "WARNING")
            except Exception as e:
                log(f"Unexpected error: {e}", "ERROR")
                time.sleep(1)


def main():
    if "-t" in sys.argv:
        sys.exit(0)

    daemonize()

    try:
        config = load_config()
    except FileNotFoundError as e:
        log(str(e), "ERROR")
        sys.exit(1)

    MAX_RETRIES = 10
    retries = 0
    while not is_indexer_ready(config):
        if retries >= MAX_RETRIES:
            log("Indexer not ready after multiple attempts. Exiting.", "ERROR")
            break
        log(f"Indexer not ready. Retrying in 1 seconds... ({retries + 1}/{MAX_RETRIES})", "WARNING")
        time.sleep(1)
        retries += 1

    log("Starting alert forwarder...")
    pid = os.getpid()
    pid_path = f"/var/ossec/var/run/wazuh-forwarder-{pid}.pid"
    with open(pid_path, "w") as f:
        f.write(str(pid))

    forwarder = AlertForwarder(config)
    try:
        forwarder.run()
    except KeyboardInterrupt:
        log("Interrupted by user. Exiting.", "INFO")


if __name__ == "__main__":
    main()
