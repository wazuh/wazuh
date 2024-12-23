# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import argparse
import json
import re
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

MOCK_RESPONSE = {
    'data': {
        'major': [],
        'minor': [
            {
                'description': '',
                'published_date': '2024-05-10T16:06:52Z',
                'semver': {'major': 4, 'minor': 9, 'patch': 0},
                'tag': 'v4.9.0',
                'title': 'Wazuh v4.9.0',
            },
        ],
        'patch': [],
    }
}


class Handler(BaseHTTPRequestHandler):
    """Custom HTTP request handler to respond to Wazuh's CTI service requests."""

    def do_GET(self):  # noqa: N802
        if re.search('/cti/v1/ping', self.path):
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()

            # Return JSON mock response
            data = json.dumps(MOCK_RESPONSE).encode('utf-8')
            self.wfile.write(data)
        else:
            self.send_response(403)
            self.end_headers()


def _argparse() -> argparse.Namespace:
    """Parse command line arguments.

    Returns
    -------
    argparse.Namespace
        Simple object for storing attributes.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        'port', action='store', default=4041, type=int, nargs='?', help='Specify alternate port [default: 4041]'
    )
    return parser.parse_args()


def main():
    args = _argparse()

    server = HTTPServer(('0.0.0.0', args.port), Handler)
    try:
        print(f'Listening on port {args.port}...', file=sys.stderr)
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()


if __name__ == '__main__':
    main()
