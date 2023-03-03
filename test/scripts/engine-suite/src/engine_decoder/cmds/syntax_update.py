from pathlib import Path
import shared.resource_handler as rs


def apply_in_decoders(resource_handler, directory, method):
    modified_files = []
    path = Path(directory)
    for p in path.rglob('*.yml'):
        # get dict from file
        base_file = resource_handler.load_file(str(p), rs.Format.YML)
        file_replaced = method(str(base_file))
        # print('base_file: ' + str(base_file))
        # print('file_replaced: ' + file_replaced)
        # compare both dicts
        if file_replaced != base_file:
            print('modified ' + str(p))
            modified_files.append(p)
    return modified_files


def helper_function_name_change(resource_handler, directory, oldName, newName):
    # TODO: check before if it has the sign to let the user choose what's better
    oldNameHelper = '+' + oldName
    newNameHelper = '+' + newName
    print('From ' + oldNameHelper + ' to ' + newNameHelper)

    # Instance of modification function
    def name_replace_helper_function(oldName, newName):
        def modification(file_string):
            #replace all string on any key of dict
            file_string = file_string.replace(oldName, newName)
            return file_string
        return modification

    modifiedFiles = apply_in_decoders(
        resource_handler, directory, name_replace_helper_function(oldNameHelper, newNameHelper))
    return len(modifiedFiles)


def run(args, resource_handler: rs.ResourceHandler):
    oldName = args['old-name']
    newName = args['new-name']
    directory = args['directory']

    if not oldName or not newName:
        print("old-name and new-name paramaters are needed.")
        exit(1)

    print(f'Replacing Helper Function Name')
    files_modified = helper_function_name_change(
        resource_handler, directory, oldName, newName)
    if files_modified > 0:
        print('Success ' + str(files_modified) + ' decoders updated.')
        print('Update decoders to make changes effective.')
    else:
        print('None decoder was updated.')


def configure(subparsers):
    parser_update_syntax = subparsers.add_parser(
        'helper-function', help='Change the helper function name on all the decoders')

    parser_update_syntax.add_argument(
        '-o', '--old-name', help=f'Helper Function Name to be changed', type=str, dest='old-name')

    parser_update_syntax.add_argument(
        '-n', '--new-name', help=f'New Helper Function Name', type=str, dest='new-name')

    parser_update_syntax.add_argument('-d', '--directory', help=f'Directory where to look for decoders', type=str, dest='directory',
                                      default='/home/vagrant/engine/wazuh/src/engine/ruleset/decoders')

    parser_update_syntax.set_defaults(func=run)
