#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.utils import cut_array, sort_array, search_array, md5, send_request
from wazuh.exception import WazuhException
from wazuh import common
from datetime import datetime
from hashlib import sha512
from time import time, mktime
import time
from os import path, listdir, rename, utime, environ, umask
from subprocess import check_output
import requests
from multiprocessing import Pool
from contextlib import contextmanager
import os
from shutil import rmtree
from io import BytesIO

CLUSTER_ITEMS = [
    {
        "file_name":"/etc/client.keys",
        "umask": 0o117, # Allowed Permissions rw-rw----
        "format":"plain",
        "type": "file",
        "write_mode": "atomic",
        "conditions": {
            "higher_remote_time": True,
            "different_md5": True,
            "larger_remote_size": True
        }
    },
    {
        "file_name":"/queue/agent-info",
        "umask": 0o117, # Allowed Permissions rw-rw----
        "format":"plain",
        "type": "directory",
        "write_mode": "normal",
        "conditions": {
            "higher_remote_time": True,
            "different_md5": False,
            "larger_remote_size": False
            }
    },
    {
        "file_name":"/queue/agent-groups",
        "umask": 0o117, # Allowed Permissions rw-rw----
        "format":"plain",
        "type": "directory",
        "write_mode": "normal",
        "conditions": {
            "higher_remote_time": True,
            "different_md5": False,
            "larger_remote_size": False
            }
    }
    # {"file_name":"/etc/ossec.conf", "format":"xml"},
]

import zipfile

try:
    import zlib
    compression = zipfile.ZIP_DEFLATED
except:
    compression = zipfile.ZIP_STORED


def compress_files(list_path, node_orig):

    zip_name = '/stats/api_cluster_{0}_{1}.zip'.format(node_orig, time.strftime("%Y-%m-%d_%H-%M-%S"))

    modes = { zipfile.ZIP_DEFLATED: 'deflated', zipfile.ZIP_STORED: 'stored' }

    zf = zipfile.ZipFile("{0}{1}".format(common.ossec_path, zip_name), mode='w')
    try:
        for f in list_path:
            try:
                zf.write(filename = common.ossec_path + f, arcname = f, compress_type=compression)
            except Exception as e:
                raise WazuhException(3001, str(e))
    finally:
        zf.close()

    return zip_name

def read_config():
    # Get api/configuration/config.js content
    try:
        with open(common.api_config_path) as api_config_file:
            lines = filter(lambda x: x.startswith('config.cluster.'),
                           api_config_file.readlines())

        name_vars = map(lambda x: x.partition("=")[::2], lines)
        config_cluster = {name.strip().split('config.')[1]:
                          var.replace("\n","").replace("]","").replace("[","").\
                          replace('\"',"").replace(";","").strip()
                          for name,var in name_vars}

        if "cluster.nodes" in config_cluster.keys():
            all_nodes = config_cluster["cluster.nodes"].split(",")
            config_cluster['cluster.nodes'] = [node.strip() for node in all_nodes]
        else:
            config_cluster["cluster.nodes"] = []

    except Exception as e:
        raise WazuhException(3000, str(e))

    return config_cluster


get_localhost_ips = lambda: check_output(['hostname', '--all-ip-addresses']).split(" ")[:-1]

def get_nodes(session=requests.Session()):
    config_cluster = read_config()
    if not config_cluster:
        raise WazuhException(3000, "No config found")

    # list with all the ips the localhost has
    localhost_ips = get_localhost_ips()
    data = []

    for url in config_cluster["cluster.nodes"]:
        # Split http(s)://x.x.x.x:55000 in just x.x.x.x
        if not url.split(':')[1][2:] in localhost_ips:
            req_url = '{0}{1}'.format(url, "/cluster/node")
            error, response = send_request(req_url, config_cluster["cluster.user"],
                                config_cluster["cluster.password"], False, "json",session)
        else:
            error = 0
            url = "localhost"
            response = {'data': get_node()}

        if error:
            data.append({'error': response, 'status':'disconnected', 'url':url})
            continue

        if 'data' in response:
            data.append({'url':url, 'node':response['data']['node'],
                         'status':'connected', 'cluster':response['data']['cluster']})
        else:
            data.append({'error': response['message'], 'status':'Unknown', 'url':url})
            continue


    return {'items': data, 'totalItems': len(data)}


def get_node(name=None):

    data = {}
    if not name:
        config_cluster = read_config()

        if not config_cluster:
            raise WazuhException(3000, "No config found")

        data["node"] = config_cluster["cluster.node"]
        data["cluster"] = config_cluster["cluster.name"]

    return data


def get_files():
    # Expand directory
    expanded_items = []
    for item in CLUSTER_ITEMS:
        file_path = item['file_name']

        if item["type"] == "file":
            new_item = dict(item)
            new_item["path"] = file_path
            expanded_items.append(new_item)
        else:
            fullpath = common.ossec_path + file_path
            for entry in listdir(fullpath):
                new_item = dict(item)
                new_item["path"] = path.join(file_path, entry)
                expanded_items.append(new_item)

    final_items = {}
    for new_item in expanded_items:
        fullpath = common.ossec_path + new_item["path"]
        if not path.isfile(fullpath):
            continue

        modification_time = str(datetime.utcfromtimestamp(int(path.getmtime(fullpath))))
        size = path.getsize(fullpath)
        md5_hash = md5(fullpath)

        file_item = {
            new_item["path"] : {
                "umask" : new_item['umask'],
                "format" : new_item['format'],
                "write_mode" : new_item['write_mode'],
                "conditions" : new_item['conditions'],

                "md5": md5_hash,
                "modification_time" : modification_time,
                "size" : size
                }
            }

        final_items.update(file_item)

    return final_items


def get_token():
    config_cluster = read_config()

    if not config_cluster:
        raise WazuhException(3000, "No config found")

    raw_key = config_cluster["cluster.key"]
    token = sha512(raw_key).hexdigest()
    return token


def _check_token(other_token):
    my_token = get_token()
    if my_token == other_token:
        return True
    else:
        return False


def _update_file(fullpath, content, umask_int=None, mtime=None, w_mode=None, type="file"):
    """
    Type param can be either
        - file: the var content has a filepath
        - text: the var content has the content of the file in a string
    """
    if type == 'file':
        l_file = open(content, "r")
        new_content = l_file.read()
        l_file.close()
    else:
        new_content = content

    # Set Timezone to epoch converter
    environ['TZ']='UTC'

    # Write
    if w_mode == "atomic":
        f_temp = '{0}.tmp.cluster'.format(fullpath)
    else:
        f_temp = '{0}'.format(fullpath)

    if umask_int:
        oldumask = umask(umask_int)

    dest_file = open(f_temp, "w")
    dest_file.write(new_content)

    if umask_int:
        umask(oldumask)

    dest_file.close()

    mtime_epoch = int(mktime(datetime.strptime(mtime, "%Y-%m-%d %H:%M:%S").timetuple()))
    utime(f_temp, (mtime_epoch, mtime_epoch)) # (atime, mtime)

    # Atomic
    if w_mode == "atomic":
        rename(f_temp, fullpath)


def _get_download_files_list(node, config_cluster, local_files, own_items, force, session):
    # local_files -> set
    download_list, discard_list, error_list = [], [], []

    # Get remote token
    url = '{0}{1}'.format(node, "/cluster/node/token")
    error, response = send_request(url, config_cluster["cluster.user"],
                          config_cluster["cluster.password"], False, "json", session)

    if error:
        error_list.append({'node': node, 'error': response})
        return download_list, discard_list, error_list

    remote_node_token = response['data']
    if not _check_token(remote_node_token):
        error_list.append({'node': node, 'error': "Invalid cluster token"})
        return download_list, discard_list, error_list

    # Get remote files
    url = '{0}{1}'.format(node, "/cluster/node/files")
    error, response = send_request(url, config_cluster["cluster.user"],
                          config_cluster["cluster.password"], False, "json", session)

    if error:
        error_list.append({'node': node, 'error': response})
        return download_list, discard_list, error_list

    their_items = response["data"]
    remote_files = set(response['data'].keys())

    # Set of files
    missing_files_locally = remote_files - local_files
    missing_files_remotely =  local_files - remote_files
    shared_files = local_files.intersection(remote_files)

    # Shared files
    for filename in shared_files:
        local_file_time = datetime.strptime(own_items[filename]["modification_time"],
                                            "%Y-%m-%d %H:%M:%S")
        local_file_size = own_items[filename]["size"]
        local_file = {
            "name": filename,
            "umask" : own_items[filename]['umask'],
            "write_mode" : own_items[filename]['write_mode'],
            "conditions" : own_items[filename]['conditions'],
            "md5": own_items[filename]["md5"],
            "modification_time": own_items[filename]["modification_time"],
            "size" : own_items[filename]['size']
        }

        remote_file_time = datetime.strptime(their_items[filename]["modification_time"],
                                            "%Y-%m-%d %H:%M:%S")
        remote_file_size = their_items[filename]["size"]
        remote_file = {
            "name": filename,
            # The umask must be the umask the file has locally. Not the one
            # the remote file has.
            "umask" : own_items[filename]['umask'],
            "write_mode" : their_items[filename]['write_mode'],
            "conditions" : their_items[filename]['conditions'],
            "md5": their_items[filename]["md5"],
            "modification_time": their_items[filename]["modification_time"],
            "size": their_items[filename]["size"]
        }


        checked_conditions = []
        conditions = {}

        if not force:
            if remote_file["conditions"]["different_md5"]:
                checked_conditions.append("different_md5")
                if remote_file["md5"] != local_file["md5"]:
                    conditions["different_md5"] = True
                else:
                    conditions["different_md5"] = False

            if remote_file["conditions"]["higher_remote_time"]:
                checked_conditions.append("higher_remote_time")
                if remote_file_time > local_file_time:
                    conditions["higher_remote_time"] = True
                else:
                    conditions["higher_remote_time"] = False

            if remote_file["conditions"]["larger_remote_size"]:
                checked_conditions.append("larger_remote_size")
                if remote_file_size > local_file_size:
                    conditions["larger_remote_size"] = True
                else:
                    conditions["larger_remote_size"] = False
        else:
            conditions["force"] = True

        check_item = {
            "file": remote_file,
            "checked_conditions": conditions,
            "updated": False,
            "node": node
        }

        all_conds = 0
        for checked_condition in checked_conditions:
            if conditions[checked_condition]:
                all_conds += 1
            else:
                break

        if all_conds == len(checked_conditions):
            download_list.append(check_item)
        else:
            discard_list.append(check_item)

    # Missing files
    for filename in missing_files_locally:
        remote_umask = CLUSTER_ITEMS[0]['umask'] if filename == CLUSTER_ITEMS[0]['file_name'] else CLUSTER_ITEMS[1]['umask']
        remote_file = {
            "name": filename,
            "umask" : remote_umask,
            "write_mode" : their_items[filename]['write_mode'],
            "conditions" : their_items[filename]['conditions'],
            "md5": their_items[filename]["md5"],
            "modification_time": their_items[filename]["modification_time"],
            "size": their_items[filename]["size"]
        }

        remote_item = {
            "file": remote_file,
            "checked_conditions": { "missing": True},
            "updated": False,
            "node": node
        }

        download_list.append(remote_item)

    return download_list, discard_list, error_list


def extract_files(path_zip_file):

    if os.path.exists("{0}/stats/downloaded.zip".format(common.ossec_path)):
        os.remove("/var/ossec/stats/downloaded.zip")

    f_out = open("{0}/stats/downloaded.zip".format(common.ossec_path), 'w')
    f_out.write(path_zip_file)
    f_out.close()

    if os.path.exists("{0}/stats/downloaded_dir".format(common.ossec_path)):
        rmtree("{0}/stats/downloaded_dir".format(common.ossec_path))

    zip_ref = zipfile.ZipFile("{0}/stats/downloaded.zip".format(common.ossec_path), 'r')
    zip_ref.extractall("{0}/stats/downloaded_dir".format(common.ossec_path))
    zip_ref.close()

    # /var/ossec/stats/downloaded_dir/var/

    extracted_list = []
    for root, directories, filenames in os.walk("{0}/stats/downloaded_dir".format(common.ossec_path)):
        for filename in filenames:
            extracted_list.append(os.path.join(root,filename))
    return extracted_list


def _download_and_update(node, config_cluster, local_files, own_items, force, session, type="text"):

    error_list, sychronize_list, local_discard_list = [], [], []

    try:
        download_list, local_discard_list, error_list = _get_download_files_list(node, config_cluster, local_files, own_items, force, session)
    except Exception as e:
        error_list.append({'node': node, 'error': str(e)})
        return error_list, sychronize_list, local_discard_list

    # Download zip
    filenames_list = []
    for item in download_list:
        filenames_list.append(item["file"]["name"])

    request_args = { "list_path": filenames_list, "node_orig": config_cluster['cluster.node']}

    try:
        url = '{0}{1}'.format(node, "/cluster/node/zip")

        error, downloaded_file = send_request(url, config_cluster["cluster.user"], config_cluster["cluster.password"], False, "text", session, method="post", data=request_args)

        if error:
            error_list.append({'node': node, 'reason': "{0} - {1}".format(str(error), str(downloaded_file))})
            return error_list, sychronize_list, local_discard_list

    except Exception as e:
        error_list.append({'node': node, 'reason': str(e)})
        return error_list, sychronize_list, local_discard_list

    new_download_list = []
    if type=="file":
        # Extrac zip: downloaded_file
        zip_files = extract_files(downloaded_file)

        for item in download_list:
            for zip_item in zip_files:
                if item['file']['name'] in zip_item:
                    item['file']['zip_path'] = zip_item
                    new_download_list.append(item)
    else:
        with zipfile.ZipFile(BytesIO(downloaded_file)) as zipf:
            # filenames in namelist have not the first /. We must include it
            # example: item['file']['name'] -> /queue/agent-info/...
            #          zip_item             -> queue/agent-info/...
            zip_namelist = list(map(lambda x: '/'+x, zipf.namelist()))
            for item in filter(lambda x: x['file']['name'] in zip_namelist, download_list):
                # added a / to make the intersection of both lists, to open it on zip file
                # we have to remove it, using [1:]
                item['file']['zip_path'] = zipf.open(item['file']['name'][1:]).read()
                new_download_list.append(item)

    for item in new_download_list:
        # print "+++ \tnode: {0} file: {1}".format(node, item['file']['name'])

        try:
            file_path = common.ossec_path + item['file']['name']
            _update_file(file_path, content=item['file']['zip_path'],
            umask_int=item['file']['umask'],
            mtime=item['file']['modification_time'],
            w_mode=item['file']['write_mode'], type=type)

        except Exception as e:
            error_list.append({'item': item, 'reason': str(e)})
            continue

        item["updated"] = True
        sychronize_list.append(item)

    return error_list, sychronize_list, local_discard_list


def _download_and_update_wrapper(args):
    return _download_and_update(*args)

@contextmanager
def terminating(thing):
    try:
        yield thing
    finally:
        thing.terminate()

def sync(debug, output_file=False, force=None):
    """
    Sync this node with others
    :return: Files synced.
    """
    session = requests.Session()

    discard_list = []
    sychronize_list = []
    error_list = []

    #Cluster config
    config_cluster = read_config()
    if not config_cluster:
        raise WazuhException(3000, "No config found")

    #Get its own files status
    own_items = get_files()
    local_files = own_items.keys()

    # Get cluster nodes
    cluster = map(lambda x: x['url'], get_nodes(session)['items'])

    for node in cluster:
        if node != 'localhost':
            local_error_list, local_synchronize_list,\
                local_discard_list = _download_and_update(node, config_cluster,
                    set(local_files), own_items, force, session)
            error_list.extend(local_error_list)
            sychronize_list.extend(local_synchronize_list)
            discard_list.extend(local_discard_list)


    if debug:
        final_output = {
            'discard': discard_list,
            'error': error_list,
            'updated': sychronize_list
        }
    else:
        final_output = {
            'discard': len(discard_list),
            'error': error_list,
            'updated': len(sychronize_list)
        }


    if output_file:
        f_o = open("{0}/logs/cluster.log".format(common.ossec_path), "a+")

        f_o.write("### {0}\n".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

        try:
            for key in final_output:
                f_o.write("\n{0}:\n".format(key))
                if key != "error":
                    for final_item in final_output[key]:
                        f_o.write("\tNode: {0}\n".format(final_item['node']))
                        f_o.write("\t\tFile: {0}\n".format(final_item['file']['name']))
                        f_o.write("\t\tChecked conditions: {0}\n".\
                                    format(final_item['checked_conditions']))
                else:
                    for final_item in final_output[key]:
                        f_o.write("\t{0}\n".format(final_item))
        except:
            f_o.write("\tError logging\n")

        f_o.write("\n###\n")
        f_o.close()

    return final_output

