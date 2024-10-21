import subprocess
import shlex
import toml
import time
from typing import Optional

from api_communication.client import APIClient
from api_communication.proto import router_pb2 as api_router


class EngineHandler:
    """EngineHandler class is responsible for starting and stopping an Engine process"""

    def __init__(self, binary_path: str, configuration_path: str) -> None:
        """Constructor for EngineHandler class

        Args:
            binary_path (str): Path to the engine binary
            configuration_path (str): Path to the engine configuration file
        """

        self.binary_path = binary_path
        self.configuration_path = configuration_path
        self.process: Optional[subprocess.Popen] = None

        self.api_socket_path = toml.load(configuration_path)[
            "server"]["api_socket"]
        self.api_client = APIClient(self.api_socket_path)

    def _wait_to_live(self) -> bool:
        """Waits for the engine process to be live

        Returns:
            bool: True if the engine process is live, False otherwise

        Raises:
            Exception: If the engine process is unresponsive
        """

        # Check if the process is live
        if self.process is None or self.process.poll() is not None:
            return False

        max_attempts = 10
        current_attempt = 0
        request = api_router.TableGet_Request()

        while current_attempt < max_attempts:
            error, _ = self.api_client.send_recv(request)
            if error == None:
                break

            time.sleep(1)
            current_attempt += 1

        if current_attempt == max_attempts:
            self.stop()
            raise Exception(
                f"All attempts exhausted after {max_attempts} tries. The operation could not be completed.")

        return True

    def start(self, log_file_path: str = "") -> None:
        """Starts the engine process

        Raises:
            Exception: If the engine process fails to start or exits with a non-zero code
        """

        command = f"{self.binary_path} --config {self.configuration_path} server start"

        if log_file_path:
            with open(log_file_path, "w") as log_file:
                self.process = subprocess.Popen(
                    shlex.split(command),
                    stdout=log_file,
                    stderr=log_file
                )
        else:
            self.process = subprocess.Popen(shlex.split(command))

        # Check if the process has started successfully
        if self.process.returncode is not None and self.process.returncode != 0:
            raise Exception(
                f"Error: Process exited with code {self.process.returncode}")

        # Wait for the engine process to be live
        if not self._wait_to_live():
            raise Exception("Engine process failed to start")

    def stop(self) -> None:
        """Stops the engine process"""
        if self.process is None or self.process.poll() is not None:
            return

        self.process.terminate()
        self.process.wait()
