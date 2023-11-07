from datetime import datetime
from enum import Enum
import json
from api_communication.client import APIClient
from api_communication.proto import test_pb2 as api_test
from api_communication.proto import engine_pb2 as api_engine
from google.protobuf.json_format import ParseDict 
from google.protobuf.json_format import MessageToJson


class ApiConfig(Enum):
    OriginName = "engine-test"
    OriginModule = "engine-test"
    Component = "test"
    SessionName = "engine_test"
    Lifespan = 0
    Description = ""


class ApiConnector:
    def __init__(self, config):
        try:
            self.api_client = APIClient(config['api-socket'])
            self.session_name = ApiConfig.SessionName.value
        except Exception as ex:
            print('Could not establish communication with the API. Error: {}'.format(ex))
            exit(1)

        self.config = config

    def test_run(self, event):
        try:
            # Create test request
            request = api_test.RunPost_Request()
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

            err, response = self.api_client.send_recv(request)
            if err:
                print(err)
                exit(1)
            response_post = ParseDict(response, api_test.RunPost_Response())
            if response_post.status != api_engine.OK:
                print("Run error: {}".format(response_post.error))
                exit(1)

            return response_post
        except Exception as ex:
            print('Could not send event to TEST api. Error: {}'.format(ex))
            exit(1)

    def message_to_json(self, value):
        try:
            return json.loads(MessageToJson(value))
        except Exception as ex:
            print('Could not convert value to json. Error: {}'.format(ex))
            exit(1)

    def create_session(self):
        try:
            if self.config['session_name']:
                # Connect to TEST with an existing session
                self.session_name = self.config['session_name']
                request_get = api_test.SessionGet_Request()
                request_get.name = self.session_name
                err, response = self.api_client.send_recv(request_get)
                if err:
                    print(err)
                    exit(1)
                response_get = ParseDict(
                    response, api_test.SessionGet_Response())

                if response_get.status != api_engine.OK:
                    print("Session error: {}".format(response_get.error))
                    exit(1)

            else:
                # Connect to TEST with a temporal session with parametrized policy
                request_post = api_test.SessionPost_Request()
                self.session_name = self.get_session_name()
                request_post.name = self.session_name
                request_post.policy = self.config['policy']
                request_post.lifespan = ApiConfig.Lifespan.value
                request_post.description = ApiConfig.Description.value
                err, response = self.api_client.send_recv(request_post)
                if err:
                    print(err)
                    exit(1)
                response_post = ParseDict(
                    response, api_engine.GenericStatus_Response())

                if response_post.status != api_engine.OK:
                    print("Session error: {}".format(response_post.error))
                    exit(1)
        except Exception as ex:
            print('The session could not be created. Error: {}'.format(ex))
            exit(3)

    def delete_session(self):
        if not self.config['session_name']:
            request_delete = api_test.SessionsDelete_Request()
            request_delete.name = self.session_name
            err, response = self.api_client.send_recv(request_delete)
            if err:
                print(err)
                exit(1)
            response_delete = ParseDict(
                response, api_engine.GenericStatus_Response())
            if response_delete.status != api_engine.OK:
                print("Session error: {}".format(response_delete.error))
                exit(1)

    def get_session_name(self):
        now = datetime.now()
        return '{}_{}'.format(self.session_name, now.strftime("%Y%m%d%H%M%S%f"))
