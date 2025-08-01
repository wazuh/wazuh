#!/usr/bin/env /var/ossec/framework/python/bin/python3

import json
import time
import sys
import os
import requests

# --- Configuration section ---

# Path to the Wazuh alerts file written in JSON format (line-by-line)
ALERTS_FILE = "/var/ossec/logs/alerts/alerts.json"

# URL of the Wazuh Indexer (OpenSearch) endpoint
INDEXER_URL = "https://localhost:9200"
INDEX_NAME = "wazuh-alerts"

# TLS certificate paths for mutual authentication with the indexer
CERT_FILE = "/etc/wazuh-indexer/certs/admin.pem"       # Client certificate
KEY_FILE = "/etc/wazuh-indexer/certs/admin-key.pem"    # Client private key
CA_CERT = "/etc/wazuh-indexer/certs/root-ca.pem"       # Root CA certificate

# Path for writing stdout/stderr output of the daemon
LOG_PATH = "/var/ossec/logs/ossec.log"


def daemonize():
    """
    Run the current process as a daemon using the double-fork method.

    This ensures that the process detaches from the terminal and runs
    in the background, with stdin redirected to /dev/null and output
    redirected to a log file.
    """
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)  # Exit parent
    except OSError as e:
        print(f"[!] Fork #1 failed: {e}", file=sys.stderr)
        sys.exit(1)

    os.chdir("/")
    os.setsid()
    os.umask(0)

    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)  # Exit second parent
    except OSError as e:
        print(f"[!] Fork #2 failed: {e}", file=sys.stderr)
        sys.exit(1)

    # Redirect stdout and stderr to log file
    sys.stdout.flush()
    sys.stderr.flush()
    with open(LOG_PATH, 'ab', buffering=0) as log_file:
        os.dup2(log_file.fileno(), sys.stdout.fileno())
        os.dup2(log_file.fileno(), sys.stderr.fileno())

    # Redirect stdin to /dev/null
    with open('/dev/null', 'rb', 0) as devnull:
        os.dup2(devnull.fileno(), sys.stdin.fileno())


def is_indexer_ready():
    """
    Perform a health check on the Wazuh Indexer (OpenSearch) cluster.

    Returns:
        bool: True if the cluster is in 'green' or 'yellow' state, False otherwise.
    """
    try:
        response = requests.get(
            f"{INDEXER_URL}/_cluster/health",
            cert=(CERT_FILE, KEY_FILE),
            verify=CA_CERT,
            timeout=3
        )
        response.raise_for_status()
        status = response.json().get("status")
        print(f"[*] Indexer health: {status}")
        return status in ("green", "yellow")
    except Exception as e:
        print(f"[!] Indexer health check failed: {e}")
        return False


class AlertForwarder:
    """
    Continuously monitors the Wazuh alert log and sends each new alert
    to the Wazuh Indexer as an individual document using mutual TLS authentication.
    """

    def send_alert(self, alert):
        """
        Send a single alert document to the Indexer.

        Args:
            alert (dict): The alert data parsed from JSON.
        """
        try:
            response = requests.post(
                f"{INDEXER_URL}/{INDEX_NAME}/_doc",
                json=alert,
                cert=(CERT_FILE, KEY_FILE),
                verify=CA_CERT,
                timeout=3
            )
            response.raise_for_status()
        except requests.RequestException as e:
            print(f"[X] Failed to send alert: {e}")

    def run(self):
        """
        Monitor the alert file and forward each new line as an individual alert.

        This method:
        - Detects file rotation or truncation using inode comparison and file size.
        - Reads new lines as they are appended to the file.
        - Parses and sends alerts one by one.
        """
        last_inode = None
        f = None

        while True:
            try:
                if not is_indexer_ready():
                    print("[X] Indexer not ready. Exiting.")
                    time.sleep(1)
                    continue

                if not os.path.exists(ALERTS_FILE):
                    time.sleep(1)
                    continue

                current_inode = os.stat(ALERTS_FILE).st_ino

                # If the file was replaced or reopened, reset reader
                if f is None or last_inode != current_inode:
                    if f:
                        f.close()
                    f = open(ALERTS_FILE, "r")
                    f.seek(0, os.SEEK_END)  # Skip past existing alerts
                    last_inode = current_inode
                    print(f"[*] Reopened alert file (inode changed): {ALERTS_FILE}")
                else:
                    # Detect file truncation and reset pointer
                    if f.tell() > os.stat(ALERTS_FILE).st_size:
                        print("[*] File truncated. Rewinding to beginning.")
                        f.seek(0)

                # Read and process next line
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
                    print("[!] Malformed JSON in alert.")

            except Exception as e:
                print(f"[!] Unexpected error: {e}")
                time.sleep(1)


def main():
    """
    Entry point of the alert forwarder.

    If run with '-t', exits immediately (used for testing).
    Otherwise, daemonizes the process, verifies indexer readiness,
    and starts forwarding alerts.
    """
    if "-t" in sys.argv:
        sys.exit(0)

    daemonize()

    print("[*] Starting alert forwarder...")
    pid = os.getpid()
    pid_path = f"/var/ossec/var/run/wazuh-forwarder-{pid}.pid"
    with open(pid_path, "w") as f:
        f.write(str(pid))

    forwarder = AlertForwarder()
    try:
        forwarder.run()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Exiting.")


if __name__ == "__main__":
    main()
