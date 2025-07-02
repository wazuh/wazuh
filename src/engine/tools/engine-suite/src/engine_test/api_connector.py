from datetime import datetime
from enum import Enum
import hashlib
from api_communication.client import APIClient
from api_communication.proto import tester_pb2 as api_tester
from api_communication.proto import engine_pb2 as api_engine
from google.protobuf.json_format import ParseDict


class ApiConfig(Enum):
    OriginName = "engine-test"
    OriginModule = "engine-test"
    Component = "test"
    SessionName = "engine_test"
    Lifespan = 0
    Description = "Automatically created by engine-test"


class ApiConnector:
    def __init__(self, config):
        try:
            self.api_client = APIClient(config['api-socket'])
            self.session_name = ApiConfig.SessionName.value
        except Exception as ex:
            print('Could not establish communication with the API. Error: {}'.format(ex))
            exit(1)

        self.config = config

    def tester_run(self, event):
        try:
            # Create test request
            request = api_tester.RunPost_Request()
            request.name = self.session_name
            request.event = event

            request.namespaces.extend(self.config['namespaces'])

            if (self.config['full_verbose'] == True):
                request.trace_level = api_tester.TraceLevel.ALL
            elif (self.config['verbose'] == True):
                request.trace_level = api_tester.TraceLevel.ASSET_ONLY
            else:
                request.trace_level = api_tester.TraceLevel.NONE

            if self.config['assets']:
                request.asset_trace.extend(self.config['assets'])

            err, response = self.api_client.send_recv(request)
            if err:
                print(err)
                exit(1)
            response_post = ParseDict(response, api_tester.RunPost_Response())
            if response_post.status != api_engine.OK:
                print("\033[91mRun error: {}\033[0m".format(response_post.error))
                exit(1)

            return response_post
        except Exception as ex:
            print('Could not send event to TEST api. Error: {}'.format(ex))
            exit(1)


    def create_session(self):
        try:
            if self.config['session_name']:
                # Connect to TEST with an existing session
                self.session_name = self.config['session_name']
                request_get = api_tester.SessionGet_Request()
                request_get.name = self.session_name
                err, response = self.api_client.send_recv(request_get)
                if err:
                    print(err)
                    exit(1)
                response_get = ParseDict(
                    response, api_tester.SessionGet_Response())

                if response_get.status != api_engine.OK:
                    print("Session error: {}".format(response_get.error))
                    exit(1)

            else:
                # Connect to TEST with a temporal session with parametrized policy
                session  = api_tester.SessionPost()
                self.session_name = self.get_session_name()
                session.name = self.session_name
                session.policy = self.config['policy']
                session.lifetime = ApiConfig.Lifespan.value
                session.description = ApiConfig.Description.value

                request_post = api_tester.SessionPost_Request()
                request_post.session.CopyFrom(session)

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
            request_delete = api_tester.SessionDelete_Request()
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

    def get_session_name(self): #TODO Change to session_name
        now = datetime.now()
        hexa = hashlib.md5(now.strftime("%Y%m%d%H%M%S%f").encode('utf-8')).hexdigest()
        return '{}_{}'.format(self.session_name, hexa[-5:])
