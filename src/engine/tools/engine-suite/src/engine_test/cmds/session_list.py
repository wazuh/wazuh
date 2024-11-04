import sys
import argparse
from google.protobuf.json_format import ParseDict
from shared.dumpers import dict_to_yml

from api_communication.client import APIClient
import api_communication.proto.tester_pb2 as etester

def run(args):
    print ("List all sessions")
    return 0

def configure(subparsers):
    list_parser = subparsers.add_parser('list', help='List all sessions')
    list_parser.set_defaults(func=run)
