import argparse
import csv
from datetime import datetime
import grp
import pwd
import os
import pandas as pd
import platform
import stat
import sys
import fnmatch

wazuh_gid = -1
wazuh_uid = -1

HEADERS = ['full_filename', 'owner_name', 'group_name', 'mode',
           'type', 'prot_permissions', 'size_bytes', 'size_error']


class helper:
    @staticmethod
    def format_timestamp(timestamp):
        """
        Convert a timestamp to a formatted string.
        """
        return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

    @staticmethod
    def filemode(mode: str) -> str:
        """ Convert a file's mode to a string of the form '-rwxrwxrwx'.

        Args:
            mode (str): The mode of the file.

        Returns:
            str: The string representation of the file's mode.
        """

        _filemode_table = (
            ((stat.S_IFLNK, "l"),
             (stat.S_IFREG, "-"),
                (stat.S_IFBLK, "b"),
                (stat.S_IFDIR, "d"),
                (stat.S_IFCHR, "c"),
                (stat.S_IFIFO, "p")),

            ((stat.S_IRUSR, "r"),),
            ((stat.S_IWUSR, "w"),),
            ((stat.S_IXUSR | stat.S_ISUID, "s"),
             (stat.S_ISUID, "S"),
                (stat.S_IXUSR, "x")),

            ((stat.S_IRGRP, "r"),),
            ((stat.S_IWGRP, "w"),),
            ((stat.S_IXGRP | stat.S_ISGID, "s"),
             (stat.S_ISGID, "S"),
                (stat.S_IXGRP, "x")),

            ((stat.S_IROTH, "r"),),
            ((stat.S_IWOTH, "w"),),
            ((stat.S_IXOTH | stat.S_ISVTX, "t"),
             (stat.S_ISVTX, "T"),
                (stat.S_IXOTH, "x"))
        )

        perm = []
        for table in _filemode_table:
            for bit, char in table:
                if mode & bit == bit:
                    perm.append(char)
                    break
            else:
                perm.append("-")
        return "".join(perm)


def translate_uid(id):
    # If wazuh_uid was not set, use the default behavior
    if wazuh_uid == -1:
        return pwd.getpwuid(id)[0]
    elif id == wazuh_uid:
        return "wazuh"
    elif id == 0:
        return "root"


def translate_gid(id):
    # If wazuh_gid was not set, use the default behavior
    if wazuh_gid == -1:
        return grp.getgrgid(id)[0]
    elif id == wazuh_gid:
        return "wazuh"
    elif id == 0:
        return "root"


def get_data(item, size_check=False):
    """
    Main function to retrieve file metadata based on the operating system.
    """
    result = {}
    stat_info = os.stat(item)

    # Populate common attributes
    populate_common_attributes(result, stat_info, size_check)

    # Platform-specific attributes
    if platform.system() != 'Windows':
        populate_unix_attributes(result, item, stat_info)
    elif platform.system() == 'Windows':
        populate_windows_attributes(result, item)

    # Special cases
    handle_special_cases(result, item)

    return result


def populate_common_attributes(result, stat_info, size_check):
    """
    Populate common attributes for any operating system.
    """
    result['mode'] = oct(stat.S_IMODE(stat_info.st_mode))[2:]
    result['type'] = "file"
    result['prot_permissions'] = stat.filemode(stat_info.st_mode)

    if size_check:
        result['size_error'] = 0.2
        result['size_bytes'] = stat_info.st_size
    else:
        result['size_error'] = ''
        result['size_bytes'] = ''


def populate_unix_attributes(result, item, stat_info):
    """
    Populate attributes specific to Unix-like systems (Linux, macOS).
    """
    result['group_name'] = translate_gid(stat_info.st_gid)
    result['owner_name'] = translate_uid(stat_info.st_uid)
    result['last_modified'] = helper.format_timestamp(stat_info.st_mtime)
    result['last_accessed'] = helper.format_timestamp(stat_info.st_atime)

    if platform.system() == 'Linux' and os.path.isfile(item):
        result['created_time'] = helper.format_timestamp(stat_info.st_ctime)
    elif platform.system() == 'Darwin':  # macOS
        result['created_time'] = helper.format_timestamp(
            stat_info.st_birthtime)
        result['readonly_flag'] = bool(stat.S_ISREG(
            stat_info.st_mode) and not stat.S_IWUSR & stat_info.st_mode)


def populate_windows_attributes(result, item):
    """
    Populate attributes specific to Windows.
    """
    import win32file
    import pywintypes

    result['group_name'] = ''
    result['owner_name'] = ''
    result['last_modified'] = helper.format_timestamp(os.path.getmtime(item))
    result['last_accessed'] = helper.format_timestamp(os.path.getatime(item))
    result['created_time'] = helper.format_timestamp(os.path.getctime(item))

    try:
        file_attributes = win32file.GetFileAttributesW(item)
        result['is_hidden'] = bool(
            file_attributes & win32file.FILE_ATTRIBUTE_HIDDEN)
        result['extension'] = os.path.splitext(item)[1][1:]
        result['attributes'] = oct(file_attributes)[-4:]
        result['readonly_flag'] = bool(
            file_attributes & win32file.FILE_ATTRIBUTE_READONLY)
        result['system_flag'] = bool(
            file_attributes & win32file.FILE_ATTRIBUTE_SYSTEM)
        result['archive_flag'] = bool(
            file_attributes & win32file.FILE_ATTRIBUTE_ARCHIVE)
    except pywintypes.error as e:
        print(f"Error processing Windows file {item}: {str(e)}")
        set_default_windows_attributes(result)


def set_default_windows_attributes(result):
    """
    Set default values for Windows-specific attributes in case of an error.
    """
    result['is_hidden'] = False
    result['attributes'] = ''
    result['readonly_flag'] = False
    result['system_flag'] = False
    result['archive_flag'] = False


def handle_special_cases(result, item):
    """
    Handle special cases, such as specific files requiring different metadata.
    """
    if item == '/var/ossec/api/configuration/auth/htpasswd':
        result['group_name'] = 'root'
        result['mode'] = '0777'
        result['type'] = 'link'
        result['owner_name'] = 'root'
        result['prot_permissions'] = 'lrwxrwxrwx'


def get_current_items(scan_path='/var/ossec', ignore_names=[]):
    """ Get all the files in the specified directory and its subdirectories.

    Args:
        scan_path (str, optional): Directory to be scanned. Defaults to '/var/ossec'.
        ignore_names (list, optional): List of files to be ignored. Defaults to [].

    Returns:
        list: List of dictionaries with the file metadata.
    """
    c_items = []

    for (dirpath, dirnames, filenames) in os.walk(scan_path, followlinks=False):
        if dirpath not in ignore_names:
            for filename in filenames:
                file_path = "{0}/{1}".format(dirpath, filename)
                if not file_path.endswith('.pyc') and file_path not in ignore_names:
                    try:
                        item = {'full_filename': file_path}
                        item.update(get_data(file_path))
                        c_items.append(item)
                    except Exception as e:
                        print(f"Error processing file {file_path}: {str(e)}")

    return c_items

# ---------------------------------------------------------------------------------------------------------------


"""
    ACTION

    Parameters:
        - param1: 
    Return:

    Example:

"""


def csv_to_dict(file_path, key_column):
    data_dict = {}

    # Open the CSV file
    with open(file_path, mode='r') as file:
        csv_reader = csv.DictReader(file)

        # Populate the dictionary using the specified column as the key
        for row in csv_reader:
            key = row.get(key_column)
            if key:  # Ensure the key is valid (not None or empty)
                data_dict[key] = row

    return data_dict

# ---------------------------------------------------------------------------------------------------------------


"""
    Finds key on dict and check each field inside, if not return the differences

    Parameters:
        - param1: 
    Return:

    Example:

"""


def file_diff(mandatory_item, current_items, size_check):
    differences = {}

    for head_type in HEADERS:
        if head_type == 'size_bytes' or head_type == 'full_filename':
            continue
        elif head_type == 'size_error' and size_check:
            expected_error = float(mandatory_item[head_type])
            mandatory_size_bytes = float(mandatory_item['size_bytes'])
            difference_bytes = abs(
                float(current_items['size_bytes']) - mandatory_size_bytes)
            if (mandatory_size_bytes and (difference_bytes / mandatory_size_bytes) > expected_error):
                differences['size_bytes'] = current_items['size_bytes']
        elif mandatory_item[head_type] != current_items[head_type]:
            differences[head_type] = current_items[head_type]

    return differences

# ---------------------------------------------------------------------------------------------------------------


"""
    print a report in MarkDown forat

    Parameters:
        - mandatory_items: dictionary of mandatory items
        - not_listed: dictionary of not listed items
        - not_fully_match: dictionary of not fully matched items
        - current_items: dictionary of present items
    Return:

    Example:

"""


def printReport(mandatory_items, not_listed, not_fully_match, current_items, report_path, mandatory_items_qtty):

    left_mandatory_items = len(mandatory_items)
    unregistered_files = len(not_listed)
    qtty_not_fully_matched = len(not_fully_match)
    base_report = ""
    failed = True

    if (left_mandatory_items == 0 and unregistered_files == 0 and qtty_not_fully_matched == 0):
        failed = False

    base_report += f"""
# Checkfiles Test

## Result

**{"Failed" if failed else "Succes"}**
    """

    if failed:
        base_report += f"""
## Result Summary

* Items found: {len(current_items)}
* Items Expected: {mandatory_items_qtty}
"""

        if qtty_not_fully_matched != 0:
            base_report += f"""

## differences

### Mandatory Files Differences

{qtty_not_fully_matched} Mandatory files didn't fully matched with the expected

"""
            for item in not_fully_match:
                base_report += f"* `{item}` : {not_fully_match[item]}\n"

        if left_mandatory_items != 0:
            base_report += f"""

### Mandatory Files Not Found

{left_mandatory_items} Mandatory item/s was/where not found

"""
            for item in mandatory_items:
                base_report += f"* `{item}`\n"

        if unregistered_files != 0:
            base_report += f"""
### Found Files Not Expected

{unregistered_files} unregistered files in mandatory list

"""
            for item in not_listed:
                base_report += f"* `{item}`\n"

    if report_path != '':
        with open(report_path, 'w') as file:
            file.write(base_report)
    else:
        print(base_report)


if __name__ == "__main__":

    print("WAZUH FILES CHECKING")

    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("-r", "--report", type=str, default="",
                            help="Path where to save report.md, default stdout")
    arg_parser.add_argument("-f", "--file_csv_path", type=str,
                            default="", help="Path of the csv file to be used for checking")
    arg_parser.add_argument("-d", "--directory", type=str, default="/var/ossec",
                            help="Directory to scan and check, '/var/ossec' by default")
    arg_parser.add_argument("-b", "--base_file", type=str, default="",
                            help="Creates a base csv in path, not to be used with --report")
    arg_parser.add_argument("-wg", "--wazuh_gid", type=int,
                            help="The group id for wazuh", default=-1)
    arg_parser.add_argument("-wu", "--wazuh_uid", type=int,
                            help="The user id for wazuh", default=-1)
    arg_parser.add_argument("-s", "--size_check", action="store_false",
                            help="Disable size validation", default=True)

    # TODO:
    # arg_parser.add_argument("-i", "--ignore", type=str, help="Ignore path: /var/ossec/wodles/oscap/content,/var/ossec/api.")

    args = arg_parser.parse_args()
    wazuh_gid = args.wazuh_gid
    wazuh_uid = args.wazuh_uid
    installed_dir = args.directory
    size_check = args.size_check
    base_file_path = args.base_file

    if (base_file_path != ''):
        if args.report != '':
            sys.exit('Do not set csv file creation alongside report creation')
        print("Starting base csv creation...")
        result = get_current_items(installed_dir)
        df = pd.DataFrame(result)
        df = df.reindex(columns=HEADERS)
        df.to_csv(base_file_path, index=False, header=True, sep=',')
    else:
        csv_file_path = args.file_csv_path
        report_path = args.report

        not_listed = {}
        not_fully_match = {}

        current_items = get_current_items(installed_dir)
        mandatory_items = csv_to_dict(csv_file_path, 'full_filename')
        mandatory_items_qtty = len(mandatory_items)

        print("Scanning started...")
        failed = False
        # Separate mandatory items into exact matches and patterns
        exact_matches = {}
        glob_patterns = {}

        # Split `mandatory_items` into exact matches and glob patterns
        for key_name, fields in mandatory_items.items():
            if '*' in key_name or '?' in key_name or '[' in key_name:
                glob_patterns[key_name] = fields
            else:
                exact_matches[key_name] = fields

        for file_object in current_items:
            current_file_name = file_object['full_filename']
            matched = False

            # 1. Check for exact match first (fast O(1) lookup)
            if current_file_name in exact_matches:
                matched = True
                mandatory_item_fields = exact_matches[current_file_name]
                
                # Check for differences
                difference_dict = file_diff(mandatory_item_fields, file_object, size_check)
                if len(difference_dict) != 0:
                    failed = True
                    # Track differences using the current file name as a key
                    not_fully_match[(current_file_name, current_file_name)] = difference_dict

            # 2. Check for matches with glob patterns if no exact match found
            if not matched:
                for pattern, mandatory_item_fields in glob_patterns.items():
                    if fnmatch.fnmatch(current_file_name, pattern):
                        matched = True
                        
                        # Check for differences
                        difference_dict = file_diff(mandatory_item_fields, file_object, size_check)
                        if len(difference_dict) != 0:
                            failed = True
                            # Use (pattern, current_file_name) as a key to track differences
                            not_fully_match[(pattern, current_file_name)] = difference_dict

            # 3. If no patterns matched, consider it a "not found" case
            if not matched:
                failed = True
                not_listed[current_file_name] = file_object

        printReport(mandatory_items, not_listed,
                    not_fully_match, current_items, report_path, mandatory_items_qtty)

        if failed:
            sys.exit("Failed: Results didn't match the expected output")
