from pathlib import Path
import shared.resource_handler as rs


def apply_in_each_decoder(resource_handler, directory, method):
    modified_files = []
    path = Path(directory)
    for p in path.rglob('*.yml'):
        # TODO: Cannot use yaml reader because it looses comment and changes order
        base_file = resource_handler.read_plain_text_file(str(p))
        new_file_content = method(str(base_file))
        # check if anything has changed
        if len(new_file_content):
            modified_files.append(p.name)
            resource_handler.save_plain_text_file(
                str(p.parent), p.name, new_file_content)
    return modified_files


def name_replace_helper_function(names_list_content):
    def modification(original_file_string):
        file_string = original_file_string
        for old_name, new_name in names_list_content.items():
            # If names does not start with '+' add it
            if old_name[0] != '+': old_name = '+' + old_name
            if new_name[0] != '+': new_name = '+' + new_name
            file_string = file_string.replace(old_name, new_name)
        if original_file_string != file_string:
            return file_string
        else:
            return ""
    return modification


def run(args, resource_handler: rs.ResourceHandler):
    old_name = args['old-name']
    new_name = args['new-name']
    directory = args['directory']
    list_file_path = args['list-file']
    names_list = dict()

    # If add_mutually_exclusive_group could be use at this level this logic gets simpler
    if list_file_path and not old_name and not new_name:
        names_list = resource_handler.load_file(
            list_file_path, rs.Format.JSON)
        if not names_list:
            print("File must not be empty if used.")
            exit(1)
    elif old_name and new_name and not list_file_path:
        names_list[str(old_name)] = new_name
    else:
        print("Must choose between single function helper change (-o and -n) or list from input file (-l).")
        exit(1)

    modifiedFiles = apply_in_each_decoder(
        resource_handler, directory, name_replace_helper_function(names_list))

    if len(modifiedFiles) > 0:
        print(str(len(modifiedFiles)) + ' decoders updated.')
        for name in modifiedFiles:
            print(str(name))
        print(f'\nUpdate decoders to make changes effective.')


def configure(subparsers):
    parser_update_syntax = subparsers.add_parser(
        'helper-function', help='Change the helper function name on all the decoders')

    parser_update_syntax.add_argument(
        '-o', '--old-name', help=f'Helper Function Name to be changed', type=str, dest='old-name')

    parser_update_syntax.add_argument(
        '-n', '--new-name', help=f'New Helper Function Name', type=str, dest='new-name')

    parser_update_syntax.add_argument(
        '-l', '--list-file', help=f'Path to list of {{"old":"new"}} helper functions names', type=str, dest='list-file')

    parser_update_syntax.add_argument('-d', '--directory', help=f'Directory where to look for decoders', type=str, dest='directory',
                                      default='/home/vagrant/engine/wazuh/src/engine/ruleset/decoders')

    parser_update_syntax.set_defaults(func=run)
