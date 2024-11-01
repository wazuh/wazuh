from datetime import datetime
import grp
import hashlib
import mimetypes
import os
import pandas as pd  # TODO: try another method to avoid using external libs
import platform
import pwd
import stat


OSSEC_PATH = "/var/ossec"

_filemode_table = (
    (
        (stat.S_IFLNK, "l"),
        (stat.S_IFREG, "-"),
        (stat.S_IFBLK, "b"),
        (stat.S_IFDIR, "d"),
        (stat.S_IFCHR, "c"),
        (stat.S_IFIFO, "p"),
    ),
    ((stat.S_IRUSR, "r"),),
    ((stat.S_IWUSR, "w"),),
    ((stat.S_IXUSR | stat.S_ISUID, "s"), (stat.S_ISUID, "S"), (stat.S_IXUSR, "x")),
    ((stat.S_IRGRP, "r"),),
    ((stat.S_IWGRP, "w"),),
    ((stat.S_IXGRP | stat.S_ISGID, "s"), (stat.S_ISGID, "S"), (stat.S_IXGRP, "x")),
    ((stat.S_IROTH, "r"),),
    ((stat.S_IWOTH, "w"),),
    ((stat.S_IXOTH | stat.S_ISVTX, "t"), (stat.S_ISVTX, "T"), (stat.S_IXOTH, "x")),
)


def filemode(mode):

    perm = []
    for table in _filemode_table:
        for bit, char in table:
            if mode & bit == bit:
                perm.append(char)
                break
        else:
            perm.append("-")
    return "".join(perm)


def get_data(item):
    result = {}

    # Common attributes
    stat_info = os.stat(item)
    result["group_name"] = grp.getgrgid(stat_info.st_gid)[0]
    result["mode"] = oct(stat.S_IMODE(stat_info.st_mode))  # [2:]
    result["owner_name"] = pwd.getpwuid(stat_info.st_uid)[0]
    result["wazuh_type"] = "agent"

    if os.path.isdir(item):
        result["type"] = "directory"
    else:
        result["type"] = "file"
        result["prot_permissions"] = stat.filemode(stat_info.st_mode)

    if platform.system() == "Linux" and os.path.isfile(item):
        result["size_bytes"] = stat_info.st_size
        result["last_modified"] = datetime.fromtimestamp(stat_info.st_mtime).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        result["last_accessed"] = datetime.fromtimestamp(stat_info.st_atime).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        result["created_time"] = datetime.fromtimestamp(stat_info.st_ctime).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        result["is_hidden"] = os.path.basename(item).startswith(".")
        result["mime_type"] = mimetypes.guess_type(item)[0] or "unknown"
        result["checksum"] = hashlib.md5(open(item, "rb").read()).hexdigest()
        result["extension"] = os.path.splitext(item)[1][1:]
        result["symlink_target"] = os.readlink(item) if os.path.islink(item) else ""
        result["inode_number"] = stat_info.st_ino
        result["device_id"] = stat_info.st_dev
        result["readonly_flag"] = bool(
            stat.S_ISREG(stat_info.st_mode) and not stat.S_IWUSR & stat_info.st_mode
        )
        result["attributes"] = oct(stat_info.st_mode)[
            -4:
        ]  # File permissions as attributes
        # Not Linux
        result["is_compressed"] = False
        result["is_encrypted"] = False
        result["system_flag"] = False
        result["archive_flag"] = False

    elif platform.system() == "Darwin":  # macOS
        result["size_bytes"] = stat_info.st_size
        result["last_modified"] = datetime.fromtimestamp(stat_info.st_mtime).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        result["last_accessed"] = datetime.fromtimestamp(stat_info.st_atime).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        result["created_time"] = datetime.fromtimestamp(
            stat_info.st_birthtime
        ).strftime("%Y-%m-%d %H:%M:%S")
        result["is_hidden"] = os.path.basename(item).startswith(".")
        result["mime_type"] = mimetypes.guess_type(item)[0] or "unknown"
        result["checksum"] = hashlib.md5(open(item, "rb").read()).hexdigest()
        result["extension"] = os.path.splitext(item)[1][1:]
        result["symlink_target"] = os.readlink(item) if os.path.islink(item) else ""
        result["readonly_flag"] = bool(
            stat.S_ISREG(stat_info.st_mode) and not stat.S_IWUSR & stat_info.st_mode
        )
        result["attributes"] = oct(stat_info.st_mode)[
            -4:
        ]  # File permissions as attributes
        result["inode_number"] = stat_info.st_ino
        result["device_id"] = stat_info.st_dev
        # Not Macos
        result["is_compressed"] = False
        result["is_encrypted"] = False
        result["system_flag"] = False
        result["archive_flag"] = False

    elif platform.system() == "Windows":
        import win32file
        import pywintypes

        result["last_modified"] = datetime.fromtimestamp(
            os.path.getmtime(item)
        ).strftime("%Y-%m-%d %H:%M:%S")
        result["last_accessed"] = datetime.fromtimestamp(
            os.path.getatime(item)
        ).strftime("%Y-%m-%d %H:%M:%S")
        result["created_time"] = datetime.fromtimestamp(
            os.path.getctime(item)
        ).strftime("%Y-%m-%d %H:%M:%S")

        if os.path.isdir(item):
            result["size_bytes"] = 0
        else:
            result["size_bytes"] = stat_info.st_size

        try:
            file_attributes = win32file.GetFileAttributesW(item)
            result["is_hidden"] = bool(
                file_attributes & win32file.FILE_ATTRIBUTE_HIDDEN
            )
            result["mime_type"] = mimetypes.guess_type(item)[0] or "unknown"
            result["checksum"] = hashlib.md5(open(item, "rb").read()).hexdigest()
            result["extension"] = os.path.splitext(item)[1][1:]
            result["symlink_target"] = (
                win32file.GetFinalPathName(item)
                if win32file.GetFileAttributesW(item)
                & win32file.FILE_ATTRIBUTE_REPARSE_POINT
                else ""
            )
            result["attributes"] = oct(file_attributes)[
                -4:
            ]  # File attributes as string
            result["is_compressed"] = bool(
                file_attributes & win32file.FILE_ATTRIBUTE_COMPRESSED
            )
            result["readonly_flag"] = bool(
                file_attributes & win32file.FILE_ATTRIBUTE_READONLY
            )
            result["system_flag"] = bool(
                file_attributes & win32file.FILE_ATTRIBUTE_SYSTEM
            )
            result["archive_flag"] = bool(
                file_attributes & win32file.FILE_ATTRIBUTE_ARCHIVE
            )
            # Not WINDOWS
            result["is_encrypted"] = False
            result["inode_number"] = None
            result["device_id"] = None
        except pywintypes.error as e:
            printf(f"Error processing Windows file {item}: {str(e)}")  # logging.warning
            # Set default values for Windows-specific attributes
            result["is_hidden"] = False
            result["symlink_target"] = ""
            result["is_compressed"] = False
            result["attributes"] = ""
            result["readonly_flag"] = False
            result["system_flag"] = False
            result["archive_flag"] = False

    # Special case for htpasswd file
    if item == "{0}/api/configuration/auth/htpasswd".format(OSSEC_PATH):
        result["group_name"] = "root"
        result["mode"] = "0777"
        result["type"] = "link"
        result["owner_name"] = "root"
        result["prot_permissions"] = "lrwxrwxrwx"
        result["symlink_target"] = "/var/ossec/api/node_modules/htpasswd/bin/htpasswd"

    return result


def get_current_items(ossec_path="/var/ossec", ignore_names=[]):
    c_items = []

    for dirpath, dirnames, filenames in os.walk(ossec_path, followlinks=False):
        if dirpath not in ignore_names:
            try:
                item = {"full_filename": dirpath}
                item.update(get_data(dirpath))
                c_items.append(item)
            except Exception as e:
                print(
                    f"Error processing directory {dirpath}: {str(e)}"
                )  # logging.warning

            for filename in filenames:
                file_path = "{0}/{1}".format(dirpath, filename)
                if not file_path.endswith(".pyc") and not file_path in ignore_names:
                    try:
                        item = {"full_filename": file_path}
                        item.update(get_data(file_path))
                        c_items.append(item)
                    except Exception as e:
                        print(
                            f"Error processing file {file_path}: {str(e)}"
                        )  # logging.warning

    return c_items


if __name__ == "__main__":

    print("starting base csv")

    result = get_current_items()
    print(result)

    df = pd.DataFrame(result)

    headers = [
        "full_filename",
        "group_name",
        "mode",
        "type",
        "size_bytes",
        "owner_name",
        "prot_permissions",
        "last_modified",
        "last_accessed",
        "created_time",
        "is_hidden",
        "mime_type",
        "checksum",
        "extension",
        "symlink_target",
        "is_compressed",
        "is_encrypted",
        "attributes",
        "inode_number",
        "device_id",
        "readonly_flag",
        "system_flag",
        "archive_flag",
        "wazuh_type",
    ]

    df = df.reindex(columns=headers)

    csv_file_path = "/tmp/base_list.csv"
    df.to_csv(csv_file_path, index=False, header=True, sep=",")
