import subprocess
import shlex
import os
import time
from typing import Optional

from api_communication.client import APIClient
from api_communication.proto import router_pb2 as api_router

DEFAULT_ENGINE_RETRY_SLEEP: int = 2

class EngineHandler:
    """EngineHandler class is responsible for starting and stopping an Engine process"""

    def __init__(self, binary_path: str, configuration_path: str, override_env : dict[str, str] = {}):
        """Constructor for EngineHandler class

        Args:
            binary_path (str): Path to the engine binary
            configuration_path (str): Path to the environment configuration file (for engine configuration)
            override_env (dict[str, str]): Dictionary of environment variables to override
        """

        self.binary_path = binary_path
        self.configuration_path = configuration_path
        self.process: Optional[subprocess.Popen] = None
        self.config_env : dict[str, str] = {} # Environment variables from the configuration file and overrides

        # Read, override and store the environment configuration
        self._read_environment_from_file()
        for key, value in override_env.items():
            self.config_env[key] = value

        self.api_socket_path = self.config_env.get("WAZUH_SERVER_API_SOCKET")
        if self.api_socket_path is None:
            raise KeyError("Environment variable 'WAZUH_SERVER_API_SOCKET' not found for the engine configuration")

        self.api_client = APIClient(self.api_socket_path)

    def _read_environment_from_file(self) -> None:
        """Read the environment configuration file"""
        with open(self.configuration_path, 'r') as file:
            for line in file:
                line = line.strip()
                if line and not line.startswith('#'):  # Ignore empty lines and comments
                    key, value = line.split('=', 1)
                    self.config_env[key] = value

    def _set_env(self) -> None:
        """Sets the environment variables for the engine process"""

        for key, value in self.config_env.items():
            os.environ[key] = value

    def _unset_env(self) -> None:
        """Unsets the environment variables for the engine process"""

        for key in self.config_env.keys():
            del os.environ[key]

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

            time.sleep(DEFAULT_ENGINE_RETRY_SLEEP)
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

        # Set the environment variables (engine configuration)
        self._set_env()

        if log_file_path:
            with open(log_file_path, "w") as log_file:
                self.process = subprocess.Popen(
                    shlex.split(self.binary_path),
                    stdout=log_file,
                    stderr=log_file
                )
        else:
            self.process = subprocess.Popen(shlex.split(self.binary_path))

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
        self._unset_env() # Unset the environment variables after stopping the process

    def get_pid(self) -> int:
        """Gets the PID of the engine process

        Returns:
            int: The PID of the engine process
        """

        if self.process is None:
            raise Exception("Engine process is not running")

        return self.process.pid
