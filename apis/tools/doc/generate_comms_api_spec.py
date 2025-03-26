"""The script will genereate the OpenAPI spec for the communication API."""

import argparse
import filecmp
from pathlib import Path

import yaml
from comms_api.routers.router import router
from fastapi import FastAPI

parser = argparse.ArgumentParser(prog='generate_comms_api_spec.py')
parser.add_argument('--output-file', help='Output file ending in .yaml', required=True, type=Path)

TMP_SPEC = Path('/tmp', 'spec.yaml')


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

    with open(TMP_SPEC, 'w') as f:
        yaml.dump(app.openapi(), f, sort_keys=False)

    if not filecmp.cmp(TMP_SPEC, spec_path):
        TMP_SPEC.rename(spec_path)
        exit(1)


if __name__ == '__main__':
    args = parser.parse_args()
    main(args.output_file)
