import subprocess
import shlex
import os
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
            configuration_path (str): Path to the environment configuration file (for engine configuration)
        """

        self.binary_path = binary_path
        self.configuration_path = configuration_path
        self.process: Optional[subprocess.Popen] = None

        self._load_environment_from_file()
        self.api_socket_path = self._get_env('WAZUH_SERVER_API_SOCKET')
        self.api_client = APIClient(self.api_socket_path)

    def _load_environment_from_file(self) -> None:
        """Loads the environment configuration file"""
        with open(self.configuration_path, 'r') as file:
            for line in file:
                line = line.strip()
                if line and not line.startswith('#'):  # Ignora líneas vacías y comentarios
                    key, value = line.split('=', 1)
                    os.environ[key] = value

    def _get_env(self, key: str) -> str:
        """Gets the value of an environment variable

        Args:
            key (str): The environment variable key

        throws:
            KeyError: If the environment variable is not found
        Returns:
            str: The value of the environment variable
        """

        # Check if the environment variable exists
        if key not in os.environ:
            raise KeyError(f"Environment variable '{key}' not found for the engine configuration")
        return os.environ[key]

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

    def start(self) -> None:
        """Starts the engine process

        Raises:
            Exception: If the engine process fails to start or exits with a non-zero code
        """

        self.process = subprocess.Popen(shlex.split(f"{self.binary_path}"))

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
