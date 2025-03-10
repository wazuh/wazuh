"""The script will genereate the OpenAPI spec for the communication API."""

import argparse

import yaml
from comms_api.routers.router import router
from fastapi import FastAPI

parser = argparse.ArgumentParser(prog='generate_comms_api_spec.py')
parser.add_argument('--output-file', help='Output file ending in .yaml', required=True)


def main(spec_path):  # NOQA
    app = FastAPI(
        title='Communications API REST',
        version='5.0.0',
        description=(
            'The Communications API is an open-source RESTful API that allows '
            'the agents communications with the manager.'
        ),
    )
    app.include_router(router)

    with open(spec_path, 'w') as f:
        yaml.dump(app.openapi(), f, sort_keys=False)


if __name__ == '__main__':
    args = parser.parse_args()
    main(args.output_file)
