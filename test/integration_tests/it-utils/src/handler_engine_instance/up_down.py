import os
import subprocess
import shlex
import time
from api_communication.client import APIClient
from api_communication.proto import router_pb2 as api_router
from pathlib import Path

BINARY_PATH = (Path(os.environ.get("BINARY_DIR", ""))).resolve().as_posix()
CONF_FILE = os.environ.get("CONF_FILE", "")
ENV_DIR = os.environ.get("ENV_DIR", "")
SOCKET_PATH = (Path(ENV_DIR) / "queue/sockets/engine-api").resolve().as_posix()

api_client = APIClient(SOCKET_PATH)


class UpDownEngine:
    def __init__(self):
        self.process = None

    def wait_to_live(self):
        max_attempts = 10
        current_attempt = 0
        request = api_router.TableGet_Request()

        while current_attempt < max_attempts:
            error, response = api_client.send_recv(request)
            if error == None:
                break

            time.sleep(1)
            current_attempt += 1

        if current_attempt == max_attempts:
            raise Exception(
                f"All attempts exhausted after {max_attempts} tries. The operation could not be completed.")

    def send_stop_command(self):
        """
        Terminates a specified process and waits until it has finished.
        """
        try:
            self.process.terminate()
            print(
                f"Termination signal sent to the process with PID {self.process.pid}")
            self.process.wait()
            print(f"Process with PID {self.process.pid} has finished")
        except Exception as e:
            print(
                f"Could not find the process with PID {self.process.pid}: {e}")

    def send_start_command(self):
        try:
            """
            Executes actions before the start of all scenarios.
            """
            # Command to execute the binary in the background
            command = f"{BINARY_PATH} --config {CONF_FILE} server start"

            # Split the command into a list of arguments using shlex
            args = shlex.split(command)

            # Execute the process in the background with subprocess.Popen
            self.process = subprocess.Popen(args)

            if self.process.returncode is not None and self.process.returncode != 0:
                print(
                    f"Error: Process exited with code {self.process.returncode}")

            # Wait for a moment to ensure the process has started
            self.wait_to_live()
        except Exception as e:
            print(f"Error during process execution: {e}")
