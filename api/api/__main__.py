#!/usr/bin/env python3

import connexion

from api import encoder

#import sys
#sys.path.append("pycharm-debug-py3k.egg")
#import pydevd
#pydevd.settrace('172.17.0.1', port=12345, stdoutToServer=True, stderrToServer=True)


def main():
    app = connexion.App(__name__, specification_dir='./swagger/')
    app.app.json_encoder = encoder.JSONEncoder
    app.add_api('swagger.yaml', arguments={'title': 'Wazuh API'})
    app.run(port=8080)


if __name__ == '__main__':
    main()
