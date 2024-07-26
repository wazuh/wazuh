import shared.resource_handler as rs


def get_asset_doc_fn(resource_handler: rs.ResourceHandler, results: list):
    def fn(file_path: str):
        decoder = resource_handler.load_file(file_path, rs.Format.YML)
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

    readme_str += f'## Schema\n\n'
    try:
        schema = resource_handler.load_file('fields.yml', rs.Format.YML)
        readme_str += f'| Field | Description | Type |\n'
        readme_str += f'|---|---|---|\n'
        for field in schema:
            readme_str += f'| {field} | {schema[field]["description"]} | {schema[field]["type"]} |\n'
    except:
        pass #TODO: error message?

    decoders_doc = []
    resource_handler.walk_dir(
        'decoders', get_asset_doc_fn(resource_handler, decoders_doc))
    readme_str += f'## Decoders\n\n'
    readme_str += f'| Name | Description |\n'
    readme_str += f'|---|---|\n'
    if decoders_doc:
        for doc in decoders_doc:
            readme_str += f'{doc}\n'

    readme_str += f'## Rules\n\n'
    readme_str += f'| Name | Description |\n'
    readme_str += f'|---|---|\n'
    rules_doc = []
    resource_handler.walk_dir(
        'rules', get_asset_doc_fn(resource_handler, rules_doc))
    if rules_doc:
        for doc in rules_doc:
            readme_str += f'{doc}\n'

    readme_str += f'## Outputs\n\n'
    readme_str += f'| Name | Description |\n'
    readme_str += f'|---|---|\n'
    outputs_doc = []
    resource_handler.walk_dir(
        'outputs', get_asset_doc_fn(resource_handler, outputs_doc))
    if outputs_doc:
        for doc in outputs_doc:
            readme_str += f'{doc}\n'

    readme_str += f'## Filters\n\n'
    readme_str += f'| Name | Description |\n'
    readme_str += f'|---|---|\n'
    filters_doc = []
    resource_handler.walk_dir(
        'filters', get_asset_doc_fn(resource_handler, filters_doc))
    if filters_doc:
        for doc in filters_doc:
            readme_str += f'{doc}\n'

    readme_str += f'## Changelog\n\n'
    changelog = resource_handler.load_file('changelog.yml', rs.Format.YML)
    readme_str += f'| Version | Description | Details |\n'
    readme_str += f'|---|---|---|\n'
    for item in changelog['items']:
        try:
            readme_str += f'| {item["version"]} | {item["short"]} | {item["pr"]} |\n'
        except:
            pass #TODO: error message?

    resource_handler.create_file('README.md', readme_str)


def configure(subparsers):
    parser_generate_doc = subparsers.add_parser(
        'generate-doc', help='Generate documentation for the integration, must be run from the integration directory')

    parser_generate_doc.set_defaults(func=run)
