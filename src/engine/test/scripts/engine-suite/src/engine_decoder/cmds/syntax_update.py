from pathlib import Path
import shared.resource_handler as rs


def apply_in_each_decoder(resource_handler, directory, method):
    modified_files = []
    path = Path(directory)
    for p in path.rglob('*.yml'):
        # get string from file
        base_file = resource_handler.read_plain_text_file(str(p))
        new_file_content = method(str(base_file))
        # check if anything has changed
        if len(new_file_content):
            modified_files.append(p.name)
            resource_handler.save_plain_text_file(
                str(p.parent), p.name, new_file_content)
    return modified_files


def name_replace_helper_function(oldName, newName):
    def modification(file_string):
        new_file_string = file_string.replace(oldName, newName)
        if new_file_string != file_string:
            return new_file_string
        else:
            return ""
    return modification


def helper_function_name_change(resource_handler, directory, oldName, newName):
    # check before if it starts with '+' if not add it
    if oldName[0] != '+':
        oldName = '+' + oldName
    if newName[0] != '+':
        newName = '+' + newName
    print('Replacing ' + oldName + ' with ' + newName)

    modifiedFiles = apply_in_each_decoder(
        resource_handler, directory, name_replace_helper_function(oldName, newName))

    for name in modifiedFiles:
        print('Modified ' + str(name))

    return len(modifiedFiles)


def run(args, resource_handler: rs.ResourceHandler):
    oldName = args['old-name']
    newName = args['new-name']
    directory = args['directory']
    list_file = args['list-file']

    if list_file:
        list_file_content = resource_handler.load_file(
            list_file, rs.Format.JSON)
        if not list_file_content:
            print("File must not be empty if used.")
            exit(1)
        for key in list_file_content:
            files_modified = helper_function_name_change(
                resource_handler, directory, key, list_file_content[key])
        if files_modified > 0:
            print('Success ' + str(files_modified) + ' decoders updated.')
        else:
            print('None decoder was updated.')
    elif not oldName or not newName:
        print("If no file is used then old-name and new-name paramaters are needed.")
        exit(1)
    else:
        # TODO: couldn't unify in same dict
        files_modified = helper_function_name_change(
            resource_handler, directory, oldName, newName)
        if files_modified > 0:
            print('Success ' + str(files_modified) + ' decoders updated.')
        else:
            print('None decoder was updated.')

    print('Update decoders to make changes effective.')


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
