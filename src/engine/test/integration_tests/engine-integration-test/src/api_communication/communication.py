import socket
import json
import struct
import subprocess

class APIClient:
    def __init__(self, api_socket: str, component: str):
        self.api_socket = api_socket
        self.component = component

    def receive_all(self, sock, size):
        data = b""
        while len(data) < size:
            packet = sock.recv(size - len(data))
            if not packet:
                return None
            data += packet
        return data

    def send_command(self, resource: str, action: str, params: dict):
        try:
            client_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client_socket.connect(self.api_socket)

            # Converts the JSON string to bytes using UTF-8 encoding
            command = f'{self.component}.{resource}/{action}'
            request = {
                'version': 1,
                'command': command,
                'origin': {'name': 'engine-integration-test', 'module': 'engine-integration-test'},
                'parameters': params
            }
            print(request)
            request_raw = json.dumps(request)
            payload = bytes(request_raw , 'utf-8')

            # Pack the message with the length of the payload
            sec_msg = bytearray()
            sec_msg.extend(struct.pack('<i', len(payload)))
            sec_msg.extend(payload)

            # Send the message
            client_socket.sendall(sec_msg)

            # Receive the 4 bytes of message length
            response_length_bytes = client_socket.recv(4)

            # Unpack all 4 bytes to get the length of the response message
            response_length = struct.unpack('<i', response_length_bytes)[0]

            # Receive the complete response using the receive_al function
            response = self.receive_all(client_socket, response_length)

            # close client
            client_socket.close()

            # Decode and convert the response to a readable string (if necessary)
            response_str = response.decode("utf-8")

            # Convert response to JSON
            response_json = json.loads(response_str)
            return response_json
        except:
            raise Exception(f'Could not parse response message "{response_json}".')

class CLIClient:
    def execute_command(self, command):
        try:
            # Execute the command and capture the output
            result = subprocess.run(command, shell=True, text=True, capture_output=True, check=True)
            return result.stdout
        except subprocess.CalledProcessError as e:
            return f"Error executing the command: {e}"
