from enum import Enum
from api_communication import communication
from api_communication import test_pb2

class ApiConfig(Enum):
    OriginName = "engine-test"
    OriginModule = "engine-test"
    Socket = "/var/ossec/queue/sockets/engine-api"
    Component = "test"
    SessionName = "engine_test"
    Policy = ""
    Lifespan = 0
    Description = ""

class ApiConnector:
    def __init__(self):
        self.api_client = communication.APIClient(ApiConfig.Socket.value, ApiConfig.Component.value)
        self.create_session()

    def send_event(self, event, config):
        # Create test request
        request = test_pb2.RunPost_Request()
        request.name = ApiConfig.SessionName.value
        request.protocol_queue = chr(config['queue'])
        request.protocol_location = config['origin']
        request.event.string_value = event
        request.namespaces.extend("system")
        request.namespaces.extend("wazuh")
        request.namespaces.extend("user") # default

        # agregar namespace en los parametros
        response = self.api_client.send_command("run", "post", request)
        return response

    def create_session(self):
        # Validate session exists
        request_get = test_pb2.SessionGet_Request()
        request_get.name = ApiConfig.SessionName.value
        response = self.api_client.send_command("session", "get", request_get)
        data = response['data']

        if data['status'] != "OK":
            request_post = test_pb2.SessionPost_Request()
            request_post.name = ApiConfig.SessionName.value
            request_post.policy = ApiConfig.Policy.value
            request_post.lifespan = ApiConfig.Lifespan.value
            request_post.description = ApiConfig.Description.value
            response = self.api_client.send_command("session", "post", request_post)
            data = response['data']
            if data['status'] == 'ERROR':
                print("Session error: {}".format(response))
                exit(1)