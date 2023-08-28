import subprocess

class CLIClient:
    def __init__(self, binary_path: str, api_socket: str):
        self.binary_path = binary_path
        self.api_socket = api_socket

    def execute_command(self, command):
        try:
            words = command.split()
            arguments = [words[0], "--api_socket", self.api_socket] + words[1:]
            result = subprocess.run([self.binary_path] + arguments, text=True, capture_output=True, check=True)
            return result.returncode, result.stdout
        except subprocess.CalledProcessError as e:
            print(f"Error executing the command: {e}")
