import shared.resource_handler as rs


def fill_documentation_base(path, name, resource_handler: rs.ResourceHandler):
    doc = {}
    doc["title"] = '<title>'
    doc["overview"] = '<overview>'
    doc["compatibility"] = '<compatibility>'
    doc["configuration"] = '<configuration>'
    doc["event"] = {'module': '<event.module>', 'dataset':'<event.dataset>'}
    resource_handler.save_file(path, name, doc, rs.Format.YML)

def fill_changelog_base(path, name, resource_handler: rs.ResourceHandler):
    doc = f'''items:
    - version: <v.v.v>
      short: <v.v>
      pr: <#46546>'''
    resource_handler.create_file(path+'/'+ name, doc)

def run(args, resource_handler: rs.ResourceHandler):
    integration_name = args['name']

    resource_handler.create_dir(integration_name)
    resource_handler.create_dir(f'{integration_name}/test')
    resource_handler.create_dir(f'{integration_name}/decoders')
    resource_handler.create_dir(f'{integration_name}/rules')
    resource_handler.create_dir(f'{integration_name}/outputs')
    resource_handler.create_dir(f'{integration_name}/filters')
    resource_handler.create_dir(f'{integration_name}/agent')
    resource_handler.create_file(f'{integration_name}/fields.yml')
    resource_handler.create_file(f'{integration_name}/logpar.yml')
    resource_handler.create_file(f'{integration_name}/documentation.yml')
    fill_documentation_base(integration_name, 'documentation.yml', resource_handler)
    resource_handler.create_dir(f'{integration_name}/kvdbs')
    fill_changelog_base(integration_name, 'changelog.yml', resource_handler)


def configure(subparsers):
    parser_create = subparsers.add_parser(
        'create', help='Create a new integration project scaffold on the current directory')

    parser_create.add_argument('name', type=str,
                               help=f'Name of the integration')

    parser_create.set_defaults(func=run)
