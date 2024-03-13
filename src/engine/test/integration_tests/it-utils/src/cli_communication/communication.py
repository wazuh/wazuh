import subprocess

class CLIClient:
    """
    A client for interacting with a command-line binary via API socket.
    """

    def __init__(self, binary_path: str, api_socket: str):
        """
        Initialize the CLIClient.

        :param binary_path: The path to the binary executable.
        :param api_socket: The API socket address.
        """
        if not binary_path or not api_socket:
            raise ValueError("Both binary_path and api_socket must be provided.")
        self.binary_path = binary_path
        self.api_socket = api_socket

    def execute_command(self, command: str):
        """
        Execute a command using the provided binary and API socket.

        :param command: The command to be executed.
        :return: A tuple containing the complete command with arguments and a tuple containing the return code and the output of the command.
        """
        try:
            words = command.split()
            arguments = [words[0], "--api_socket", self.api_socket] + words[1:]
            full_command = [self.binary_path] + arguments
            result = subprocess.run(full_command, text=True, capture_output=True, check=True)
            return result.returncode, result.stdout
        except Exception as e:
            return 1, e.stderr
