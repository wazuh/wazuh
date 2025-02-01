import shared.resource_handler as rs
from pathlib import Path


def get_asset_doc_fn(resource_handler: rs.ResourceHandler, results: list):
    # Load manifest file
    manifest = resource_handler.load_file('manifest.yml', rs.Format.YML)

    def fn(file_path: str):
        decoder = resource_handler.load_file(file_path, rs.Format.YML)
        for type in manifest:
            if type is not 'name':
                if 'name' in decoder and decoder['name'] in manifest[type]:
                    doc = f'| {decoder["name"]} | {decoder["metadata"]["description"]} |'
                    results.append(doc)

    return fn


def run(_, resource_handler: rs.ResourceHandler):
    doc = resource_handler.load_file('documentation.yml', rs.Format.YML)
    readme_str = f'# "title"\n\n'
    readme_str = f'# {doc["title"]}\n\n'
    readme_str += f'''
|   |   |
|---|---|
| event.module | {doc["event"]["module"]} |'''
    if 'dataset' in doc['event']:
        readme_str += f'''
| event.dataset | {doc["event"]["dataset"]} |
'''
    readme_str += f'{doc["overview"]}\n\n'
    readme_str += f'## Compatibility\n\n'
    readme_str += f'{doc["compatibility"]}\n\n'
    readme_str += f'## Configuration\n\n'
    readme_str += f'{doc["configuration"]}\n\n'

    ruleset_path = Path(resource_handler.cwd()).parent.parent.resolve()

    decoders_doc = []
    for file in (ruleset_path / 'decoders').rglob('*.yml'):
        get_asset_doc_fn(resource_handler, decoders_doc)(file.as_posix())

    if len(decoders_doc) > 0:
        readme_str += f'## Decoders\n\n'
        readme_str += f'| Name | Description |\n'
        readme_str += f'|---|---|\n'
        for doc in decoders_doc:
            readme_str += f'{doc}\n'

    rules_doc = []
    for file in (ruleset_path / 'rules').rglob('*.yml'):
        get_asset_doc_fn(resource_handler, decoders_doc)(file.as_posix())
    if len(rules_doc) > 0:
        readme_str += f'## Rules\n\n'
        readme_str += f'| Name | Description |\n'
        readme_str += f'|---|---|\n'
        for doc in rules_doc:
            readme_str += f'{doc}\n'

    outputs_doc = []
    for file in (ruleset_path / 'outputs').rglob('*.yml'):
        get_asset_doc_fn(resource_handler, decoders_doc)(file.as_posix())
    if len(outputs_doc) > 0:
        readme_str += f'## Outputs\n\n'
        readme_str += f'| Name | Description |\n'
        readme_str += f'|---|---|\n'
        for doc in outputs_doc:
            readme_str += f'{doc}\n'

    resource_handler.create_file('README.md', readme_str)


def configure(subparsers):
    parser_generate_doc = subparsers.add_parser(
        'generate-doc', help='Generate documentation for the integration, must be run from the integration directory')

    parser_generate_doc.set_defaults(func=run)
