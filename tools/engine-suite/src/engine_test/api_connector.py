from datetime import datetime
from enum import Enum
from api_communication import communication
from api_communication import test_pb2

class ApiConfig(Enum):
    OriginName = "engine-test"
    OriginModule = "engine-test"
    Socket = "/var/ossec/queue/sockets/engine-api"
    Component = "test"
    SessionName = "engine_test"
    Lifespan = 0
    Description = ""

class ApiConnector:
    def __init__(self, config):
        try:
            self.api_client = communication.APIClient(ApiConfig.Socket.value, ApiConfig.Component.value)
            self.session_name = ApiConfig.SessionName.value
        except Exception as ex:
            print('Could not establish communication with the API. Error: {}'.format(ex))
            exit(1)

        self.config = config

    def test_run(self, event):
        try:
            # Create test request
            request = test_pb2.RunPost_Request()
            request.name = self.session_name
            request.protocol_queue = chr(self.config['queue'])
            request.protocol_location = self.config['full_location']
            request.event.string_value = event

            request.namespaces.extend(self.config['namespaces'])

            if (self.config['full_verbose'] == True):
                request.debug_mode = 2
            else:
                if self.config['verbose']:
                    request.debug_mode = 1

            if self.config['assets']:
                request.asset_trace.extend(self.config['assets'])

            response = self.api_client.send_command("run", "post", request)
            return response
        except Exception as ex:
            print('Could not send event to TEST api. Error: {}'.format(ex))
            exit(1)

    def create_session(self):
        try:
            if self.config['session_name']:
                # Connect to TEST with an existing session
                self.session_name = self.config['session_name']
                request_get = test_pb2.SessionGet_Request()
                request_get.name = self.session_name
                response = self.api_client.send_command("session", "get", request_get)
                data = response['data']

                if data['status'] == "ERROR":
                    print("Session error: {}".format(response))
                    exit(1)

            else:
                # Connect to TEST with a temporal session with parametrized policy
                request_post = test_pb2.SessionPost_Request()
                self.session_name = self.get_session_name()
                request_post.name = self.session_name
                request_post.policy = self.config['policy']
                request_post.lifespan = ApiConfig.Lifespan.value
                request_post.description = ApiConfig.Description.value
                response = self.api_client.send_command("session", "post", request_post)
                data = response['data']
                if data['status'] == 'ERROR':
                    print("Session error: {}".format(response))
                    exit(1)
        except Exception as ex:
            print('The session could not be created. Error: {}'.format(ex))
            exit(3)

    def delete_session(self):
        if not self.config['session_name']:
            request_delete = test_pb2.SessionsDelete_Request()
            request_delete.name = self.session_name
            response = self.api_client.send_command("sessions", "delete", request_delete)
            data = response['data']
            if data['status'] == 'ERROR':
                print("Session error: {}".format(response))
                exit(1)

    def get_session_name(self):
        now = datetime.now()
        return '{}_{}'.format(self.session_name, now.strftime("%Y%m%d%H%M%S%f"))
