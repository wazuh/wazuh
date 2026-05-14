# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import re
import ssl
import sys

MOCK_RESPONSE = {
    "data": {
        "api_requests_hourly": {
            "user": {
                "allowed": 240,
                "used": 0
            }
        }
    }
}

MOCK_ERROR_RESPONSE = {
    "error": {
        "code": "WrongCredentialsError",
        "message": "Wrong API key"
    }
}


class Handler(BaseHTTPRequestHandler):
    """Custom HTTP request handler to respond to Wazuh's VirusTotal API requests."""

    def do_GET(self):
        expected_api_header = 'x-apikey'
        api_key = 'expected_api_key'

        # Retrieve the header from the request
        received_header_value = self.headers.get(expected_api_header)

        if re.search(f'/api/v3/users/{api_key}/overall_quotas', self.path) and received_header_value == api_key:
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()

            data = json.dumps(MOCK_RESPONSE).encode('utf-8')
            self.wfile.write(data)
        else:
            self.send_response(401)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()

            data = json.dumps(MOCK_ERROR_RESPONSE).encode('utf-8')
            self.wfile.write(data)


def _argparse() -> argparse.Namespace:
    """Parse command line arguments.

    Returns
    -------
    argparse.Namespace
        Simple object for storing attributes.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('port', action='store', default=8080, type=int, nargs='?',
                        help='Specify alternate port [default: 8080]')
    return parser.parse_args()


def run(server_class=HTTPServer, handler_class=Handler, port=8080):
    """Run the https mock server."""
    server_address = ('0.0.0.0', port)
    httpd = server_class(server_address, handler_class)
    print(f'Starting https server on port {port}', file=sys.stderr)

    # Create an SSL context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")

    # Wrap the server's socket with the SSL context
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    try:
        print(f'Listening on port {port}...', file=sys.stderr)
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == '__main__':
    args = _argparse()

    run(port=args.port)


