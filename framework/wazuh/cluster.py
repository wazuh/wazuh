#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.utils import execute, cut_array, sort_array, search_array, chmod_r, chown_r
from wazuh.exception import WazuhException
from wazuh.database import Connection
from wazuh import manager
from wazuh import common
from glob import glob
from datetime import date, datetime
from hashlib import md5, sha512
from time import time, mktime
from platform import platform
from os import remove, chown, chmod, path, rename, stat, utime, environ
from pwd import getpwnam
from grp import getgrnam
import requests
import json

class Node:
    """
    Wazuh node object
    """

    def __init__(self, *args, **kwargs):
        """
        Initialize an node.
        'id': Node id when it exists
        'node', 'ip', 'user', 'password': Insert a new node

        :param args:   [id | node, ip, user, password].
        :param kwargs: [id | node, ip, user, password].
        """
        self.id = None
        self.node = None
        self.ip = None
        self.password = None
        self.user = None
        self.status = None


        if args:
            if len(args) == 1:
                self.id = args[0]
            else:
                raise WazuhException(1700)
        elif kwargs:
            if len(kwargs) == 1:
                self.id = kwargs['id']
            else:
                raise WazuhException(1700)

    def __str__(self):
        return str(self.to_dict())

    @staticmethod
    def cluster_nodes():

        config_cluster = cluster_get_config()
        if not config_cluster:
            raise WazuhException(3000, "No config found")

        # TODO: Add my self as a node
        data = []
        for url in config_cluster["cluster.nodes"]:
            item = {}
            item["url"] = url

            base_url = "{0}".format(url)

            auth = requests.auth.HTTPBasicAuth(config_cluster["cluster.user"], config_cluster["cluster.password"])
            verify = False
            url = '{0}{1}'.format(base_url, "/cluster/node")
            error, response = Node.send_request_api(url, auth, verify, "json")

            if error:
                item["error"] = {'api_error': response, "code": error}
                item["status"] = "disconnected"
                data.append(item)
                continue

            item["node"] = response["data"]["node"]
            item["status"] = "connected"

            data.append(item)

        return {'items': data, 'totalItems': len(data)}

    @staticmethod
    def node_info():
        config_cluster = cluster_get_config()

        if not config_cluster:
            raise WazuhException(3000, "No config found")

        data = {}
        data["node"] = config_cluster["cluster.node"]
        data["cluster"] = config_cluster["cluster.name"]

        return data

    @staticmethod
    def send_request_api(url, auth, verify, type):
        error = 0
        try:
            r = requests.get(url, auth=auth, params=None, timeout=2, verify=verify)
            if r.status_code == 401:
                  data = str(r.text)
                  error = 401
        except requests.exceptions.Timeout as e:
            data = str(e)
            error = 1
        except requests.exceptions.TooManyRedirects as e:
            data = str(e)
            error = 2
        except requests.exceptions.RequestException as e:
            data = str(e)
            error = 3
        except Exception as e:
            data = str(e)
            error = 4

        if error == 0:
            if type == "json":
                try:
                    data = json.loads(r.text)
                except Exception as e:
                    data = str(e)
                    error = 5
            else:
                data = r.text
        return (error, data)

    @staticmethod
    def update_file(fullpath, content, owner=None, group=None, mode=None, mtime=None, w_mode=None):

        # Set atomic replaces
        # w_mode = "normal"

        # Set Timezone to epoch converter
        environ['TZ']='UTC'

        # Write
        if w_mode == "atomic":
            f_temp = '{0}.tmp.cluster'.format(fullpath)
        else:
            f_temp = '{0}'.format(fullpath)

        dest_file = open(f_temp, "w")
        dest_file.write(content)
        dest_file.close()

        # Metadata
        # Disabled getting metadata from external node
        #uid = getpwnam(owner).pw_uid
        #gid = getgrnam(group).gr_gid
        #chown(f_temp, uid, gid) #  Fix me: api runs as ossec...
        #chmod(f_temp, mode)

        # Hardcoding user, group and privileges
        uid = getpwnam("ossec").pw_uid
        gid = getgrnam("ossec").gr_gid
        chown(f_temp, uid, gid) #  Fix me: api runs as ossec...
        chmod(f_temp, 0o660)

        mtime_epoch = int(mktime(datetime.strptime(mtime, "%Y-%m-%d %H:%M:%S").timetuple()))
        utime(f_temp, (mtime_epoch, mtime_epoch)) # (atime, mtime)

        # Atomic
        if w_mode == "atomic":
            rename(f_temp, fullpath)

    @staticmethod
    def get_token():
        config_cluster = cluster_get_config()

        if not config_cluster:
            raise WazuhException(3000, "No config found")

        raw_key = config_cluster["cluster.key"]
        token = sha512(raw_key).hexdigest()
        return token

    @staticmethod
    def check_token(other_token):
        my_token = Node.get_token()
        if my_token == other_token:
            return True
        else:
            return False

    @staticmethod
    def sync(output_file=False, force=None):
        """
        Sync this node with others
        :return: Files synced.
        """

        #Cluster config
        config_cluster = cluster_get_config()
        if not config_cluster:
            raise WazuhException(3000, "No config found")

        #Get its own files status
        own_items = manager.get_files()
        local_files = own_items.keys()

        #Get other nodes files
        cluster = Node()
        nodes = config_cluster["cluster.nodes"]

        discard_list = []
        synchronize_list = []
        error_list = []

        # auth
        auth = requests.auth.HTTPBasicAuth(config_cluster["cluster.user"], config_cluster["cluster.password"])
        verify = False
        for node in nodes:
            download_list = []

            # Get remote files
            url = '{0}{1}'.format(node, "/manager/files")
            error, response = Node.send_request_api(url, auth, verify, "json")

            if error:
                error_list.append({'node': node, 'api_error': response, "code": error})
                continue

            their_items = response["data"]
            remote_files = response['data'].keys()

            # Get remote token
            url = '{0}{1}'.format(node, "/cluster/node/token")
            error, response = Node.send_request_api(url, auth, verify, "json")

            if error:
                error_list.append({'node': node, 'api_error': response, "code": error})
                continue

            remote_node_token = response['data']
            if not Node.check_token(remote_node_token):
                error_list.append({'node': node, 'error': "Invalid cluster token"})
                continue


            missing_files_locally = set(remote_files) - set(local_files)
            missing_files_remotely =  set(local_files) - set(remote_files)
            shared_files = set(local_files).intersection(remote_files)

            # Shared files
            for filename in shared_files:
                own_items[filename]["modification_time"]
                local_file_time = datetime.strptime(own_items[filename]["modification_time"], "%Y-%m-%d %H:%M:%S")
                local_file_size = own_items[filename]["size"]
                local_file = {
                    "name": filename,
                    "md5": own_items[filename]["md5"],
                    "size" : own_items[filename]['size'],
                    "modification_time": own_items[filename]["modification_time"],
                    "mode" : own_items[filename]['mode'],
                    "user" : own_items[filename]['user'],
                    "group" : own_items[filename]['group'],
                    "write_mode" : own_items[filename]['write_mode'],
                    "conditions" : own_items[filename]['conditions']
                }

                remote_file_time = datetime.strptime(their_items[filename]["modification_time"], "%Y-%m-%d %H:%M:%S")
                remote_file_size = their_items[filename]["size"]
                remote_file = {
                    "name": filename,
                    "md5": their_items[filename]["md5"],
                    "size": their_items[filename]["size"],
                    "modification_time": their_items[filename]["modification_time"],
                    "mode" : their_items[filename]['mode'],
                    "user" : their_items[filename]['user'],
                    "group" : their_items[filename]['group'],
                    "write_mode" : their_items[filename]['write_mode'],
                    "conditions" : their_items[filename]['conditions']
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

                    if remote_file["conditions"]["remote_time_higher"]:
                        checked_conditions.append("remote_time_higher")
                        if remote_file_time > local_file_time:
                            conditions["remote_time_higher"] = True
                        else:
                            conditions["remote_time_higher"] = False

                    if remote_file["conditions"]["larger_file_size"]:
                        checked_conditions.append("larger_file_size")
                        if remote_file_size > local_file_size:
                            conditions["larger_file_size"] = True
                        else:
                            conditions["larger_file_size"] = False
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

                remote_file = {
                    "name": filename,
                    "md5": their_items[filename]["md5"],
                    "modification_time": their_items[filename]["modification_time"],
                    "mode" : their_items[filename]['mode'],
                    "size" : their_items[filename]['size'],
                    "user" : their_items[filename]['user'],
                    "group" : their_items[filename]['group'],
                    "write_mode" : their_items[filename]['write_mode']
                }

                remote_item = {
                    "file": remote_file,
                    "checked_conditions": { "missing": True},
                    "updated": False,
                    "node": node
                }

                download_list.append(remote_item)

            # Download


            for item in download_list:
                try:
                    url = '{0}{1}'.format(node, "/manager/files?download="+item["file"]["name"])

                    error, downloaded_file = Node.send_request_api(url, auth, verify, "text")
                    if error:
                        error_list.append({'item': item, 'reason': downloaded_file})
                        continue

                    # Fix me: wazuh path + file
                    try:
                        Node.update_file(item['file']['name'], content=downloaded_file, owner=item['file']['user'], group=item['file']['group'], mode=item['file']['mode'], mtime=item['file']['modification_time'], w_mode=item['file']['write_mode'])
                    except Exception as e:
                        error_list.append({'item': item, 'reason': str(e)})
                        continue

                except Exception as e:
                    error_list.append({'item': item, 'reason': str(e)})
                    raise
                    continue


                item["updated"] = True
                synchronize_list.append(item)

        #print check_list
        final_output = {
            'discard': discard_list,
            'error': error_list,
            'updated': synchronize_list
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
                            f_o.write("\t\tChecked conditions: {0}\n".format(final_item['checked_conditions']))
                    else:
                        for final_item in final_output[key]:
                            f_o.write("\t{0}\n".format(final_item))
            except:
                f_o.write("\tError logging\n")

            f_o.write("\n###\n")
            f_o.close()

        return final_output

def cluster_get_config():
    # Get api/configuration/config.js content
    config_cluster = {}
    try:
        with open(common.api_config_path) as api_config_file:
            for line in api_config_file:
                if line.startswith('config.cluster.'):
                    name, var = line.partition("=")[::2]
                    config_cluster[name.strip().split("config.")[1]] = var.replace("\n","").replace("]","").replace("[","").replace('\"',"").replace(";","").strip()

        if "cluster.nodes" in config_cluster:
            all_nodes = config_cluster["cluster.nodes"].split(",")
            config_cluster["cluster.nodes"] = []
            for node in all_nodes:
                config_cluster["cluster.nodes"].append(node.strip())
        else:
            config_cluster["cluster.nodes"] = []
    except Exception as e:
        raise WazuhException(3000, str(e))

    return config_cluster
