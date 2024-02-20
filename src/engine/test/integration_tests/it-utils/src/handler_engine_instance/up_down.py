import os
import signal
import subprocess
import shlex
import time

BINARY_PATH = os.environ.get("WAZUH_DIR", "") + "/src/engine/build/main"
CONF_FILE = os.environ.get("CONF_FILE", "")

class UpDownEngine:
    def __init__(self):
        self.process = None

    def send_stop_command(self):
        """
        Terminates a specified process and waits until it has finished.
        """
        try:
            self.process.terminate()
            print(f"Termination signal sent to the process with PID {self.process.pid}")
            self.process.wait()
            print(f"Process with PID {self.process.pid} has finished")
        except Exception as e:
            print(f"Could not find the process with PID {self.process.pid}: {e}")

    def send_start_command(self, ignore_level_log_of_config=True):
        try:
            """
            Executes actions before the start of all scenarios.
            """
            # Command to execute the binary in the background
            if not ignore_level_log_of_config:
                command = f"{BINARY_PATH} --config {CONF_FILE} server start"
            else:
                command = f"{BINARY_PATH} --config {CONF_FILE} server -l debug start"

            # Split the command into a list of arguments using shlex
            args = shlex.split(command)

            # Execute the process in the background with subprocess.Popen
            self.process = subprocess.Popen(args)

            if self.process.returncode is not None and self.process.returncode != 0:
                print(f"Error: Process exited with code {self.process.returncode}")

            # Wait for a moment to ensure the process has started
            time.sleep(2)
        except Exception as e:
            print(f"Error during process execution: {e}")
