import os, fnmatch

def findReplace(directory, oldName, newName):
    filePattern = '*.yml'
    modified_files = []
    for path, dirs, files in os.walk(os.path.abspath(directory)):
        for filename in fnmatch.filter(files, filePattern):
            filepath = os.path.join(path, filename)
            with open(filepath) as f:
                s = f.read()
                s_aux = s
            s = s.replace(oldName, newName)
            # list and print the files that where modified
            if s_aux != s:
                modified_files.append(filename)
                print('modified ' + filename )
            with open(filepath, 'w') as f:
                f.write(s)
    return modified_files

def hFNameChange(directory, oldName, newName):
    # TODO: check before if it has the sign
    oldNameHelper = '+' + oldName
    newNameHelper = '+' + newName
    print('From ' + oldNameHelper + ' to ' + newNameHelper)
    modifiedFiles = findReplace(directory,oldNameHelper,newNameHelper)
    return len(modifiedFiles)

def run(args, resource_handler):
    # TODO can I avoid using that seccond argument?
    oldName = args['old-name']
    newName = args['new-name']
    directory = args['directory']

    if not oldName or not newName:
        print("old-name and new-name paramaters are needed.")
        exit(1)

    print(f'Replacing Helper Function Name')
    files_modified = hFNameChange(directory, oldName, newName)
    if files_modified > 0 :
        print('Success ' + str(files_modified) + ' decoders updated.')
        print('Update decoders to make changes effective.')
    else:
        print('None decoder was updated.')


def configure(subparsers):
    parser_update_syntax = subparsers.add_parser(
        'helper-function', help='Change the helper function name on all the decoders')

    parser_update_syntax.add_argument('-o','--old-name', dest='old-name', type=str,
        help=f'HF Name to be changed')

    parser_update_syntax.add_argument('-n','--new-name', dest='new-name', type=str,
        help=f'New HF Name')

    parser_update_syntax.add_argument('-d','--directory', dest='directory',  type=str,
        help=f'Directory where to look for decoders',
        default='/home/vagrant/engine/wazuh/src/engine/ruleset/decoders')

    parser_update_syntax.set_defaults(func=run)
