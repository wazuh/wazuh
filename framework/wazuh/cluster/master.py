# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import asyncio
import json
from datetime import datetime
import functools
import operator
import os
from typing import Tuple, Dict
import fcntl
from wazuh.agent import Agent
from wazuh.cluster import server, cluster, common as c_common
from wazuh import cluster as metadata
from wazuh import common, utils, WazuhException


class MasterHandler(server.AbstractServerHandler, c_common.WazuhCommon):

    def __init__(self, **kwargs):
        super().__init__(**kwargs, tag="Worker")
        self.sync_integrity_free = True  # the worker isn't currently synchronizing integrity
        self.sync_extra_valid_free = True
        self.sync_agent_info_free = True
        self.sync_integrity_status = {'date_start_master': "n/a", 'date_end_master': "n/a",
                                      'total_files': {'missing': 0, 'shared': 0, 'extra': 0, 'extra_valid': 0}}
        self.sync_agent_info_status = {'date_start_master': "n/a", 'date_end_master': "n/a",
                                       'total_agent_info': 0}
        self.sync_extra_valid_status = {'date_start_master': "n/a", 'date_end_master': "n/a",
                                        'total_extra_valid': 0}
        self.version = ""
        self.cluster_name = ""
        self.node_type = ""

    def __dict__(self):
        return {'info': {'name': self.name, 'type': self.node_type, 'version': self.version, 'address': self.ip},
                'status': {'sync_integrity_free': self.sync_integrity_free, 'last_sync_integrity': self.sync_integrity_status,
                           'sync_agent_info_free': self.sync_agent_info_free, 'last_sync_agent_info': self.sync_agent_info_status,
                           'sync_extra_valid_free': self.sync_extra_valid_free, 'last_sync_agent_groups': self.sync_extra_valid_status,
                           'last_keep_alive': self.last_keepalive}}

    def process_request(self, command: bytes, data: bytes) -> Tuple[bytes, bytes]:
        self.logger.debug("Command received: {}".format(command))
        if command == b'sync_i_w_m_p' or command == b'sync_e_w_m_p' or command == b'sync_a_w_m_p':
            return self.get_permission(command)
        elif command == b'sync_i_w_m' or command == b'sync_e_w_m' or command == b'sync_a_w_m':
            return self.setup_sync_integrity(command)
        elif command == b'sync_i_w_m_e' or command == b'sync_e_w_m_e' or command == b'sync_a_w_m_e':
            return self.end_receiving_integrity_checksums(data.decode())
        else:
            return super().process_request(command, data)

    def hello(self, data: bytes) -> Tuple[bytes, bytes]:
        name, cluster_name, node_type, version = data.split(b' ')
        cmd, payload = super().hello(name)

        self.version, self.cluster_name, self.node_type = version.decode(), cluster_name.decode(), node_type.decode()

        if self.cluster_name != self.server.configuration['name']:
            cmd, payload = b'err', b'Worker does not belong to the same cluster'
        elif self.version != metadata.__version__:
            cmd, payload = b'err', b'Worker and master versions are not the same'

        worker_dir = '{}/queue/cluster/{}'.format(common.ossec_path, self.name)
        if cmd == b'ok' and not os.path.exists(worker_dir):
            utils.mkdir_with_mode(worker_dir)
        return cmd, payload

    def get_permission(self, sync_type: bytes) -> Tuple[bytes, bytes]:
        if sync_type == b'sync_i_w_m_p':
            permission = self.sync_integrity_free
        elif sync_type == b'sync_e_w_m_p':
            permission = self.sync_extra_valid_free
        elif sync_type == b'sync_a_w_m_p':
            permission = self.sync_agent_info_free
        else:
            permission = False

        return b'ok', str(permission).encode()

    def setup_sync_integrity(self, sync_type: bytes) -> Tuple[bytes, bytes]:
        if sync_type == b'sync_i_w_m':
            self.sync_integrity_free, sync_function = False, self.sync_integrity
        elif sync_type == b'sync_e_w_m':
            self.sync_extra_valid_free, sync_function = False, self.sync_extra_valid
        elif sync_type == b'sync_a_w_m':
            self.sync_agent_info_free, sync_function = False, self.sync_extra_valid
        else:
            sync_function = None

        return super().setup_receive_file(sync_function)

    def end_receiving_integrity_checksums(self, task_and_file_names: str) -> Tuple[bytes, bytes]:
        return super().end_receiving_file(task_and_file_names)

    async def sync_worker_files(self, task_name: str, received_file: asyncio.Task):
        self.logger.info("Waiting to receive zip file from worker")
        await received_file.wait()
        received_filename = self.sync_tasks[task_name].filename
        self.logger.debug("Received file from worker: '{}'".format(received_filename))

        files_checksums, decompressed_files_path = cluster.decompress_files(received_filename)
        self.logger.info("Analyzing worker integrity: Received {} files to check.".format(len(files_checksums)))
        self.process_files_from_worker(files_checksums, decompressed_files_path)

    async def sync_extra_valid(self, task_name: str, received_file: asyncio.Task):
        self.sync_extra_valid_status['date_start_master'] = str(datetime.now())
        await self.sync_worker_files(task_name, received_file)
        self.sync_extra_valid_free = True
        self.sync_extra_valid_status['date_end_master'] = str(datetime.now())

    async def sync_agent_info(self, task_name: str, received_file: asyncio.Task):
        self.sync_agent_info_status['date_start_master'] = str(datetime.now())
        await self.sync_worker_files(task_name, received_file)
        self.sync_agent_info_free = True
        self.sync_agent_info_status['date_end_master'] = str(datetime.now())

    async def sync_integrity(self, task_name: str, received_file: asyncio.Task):
        self.sync_integrity_status['date_start_master'] = str(datetime.now())

        self.logger.info("Waiting to receive zip file from worker")
        await received_file.wait()
        received_filename = self.sync_tasks[task_name].filename
        self.logger.debug("Received file from worker: '{}'".format(received_filename))

        files_checksums, decompressed_files_path = cluster.decompress_files(received_filename)
        self.logger.info("Analyzing worker integrity: Received {} files to check.".format(len(files_checksums)))
        self.logger.debug2(files_checksums)

        # classify files in shared, missing, extra and extra valid.
        worker_files_ko, counts = cluster.compare_files(self.server.integrity_control, files_checksums)

        # health check
        self.sync_integrity_status['total_files'] = counts

        if not functools.reduce(operator.add, map(len, worker_files_ko.values())):
            self.logger.info("Analyzing worker integrity: Files checked. There are no KO files.")
            result = await self.send_request(command=b'sync_m_c_ok', data=b'')
        else:
            self.logger.info("Analyzing worker integrity: Files checked. There are KO files.")

            # Compress data: master files (only KO shared and missing)
            self.logger.debug("Analyzing worker integrity: Files checked. Compressing KO files.")
            master_files_paths = worker_files_ko['shared'].keys() | worker_files_ko['missing'].keys()
            compressed_data = cluster.compress_files(self.name, master_files_paths, worker_files_ko)

            self.logger.debug("Analyzing worker integrity: Files checked. KO files compressed.")
            task_name = await self.send_request(command=b'sync_m_c', data=b'')
            if task_name.startswith(b'Error'):
                self.logger.error(task_name)
                return task_name

            result = await self.send_file(compressed_data)
            if result.startswith(b'Error'):
                self.logger.error(result)
                return result

            result = await self.send_request(command=b'sync_m_c_e', data=task_name + b' ' + compressed_data.encode())

        self.sync_integrity_status['date_end_master'] = str(datetime.now())
        self.sync_integrity_free = True
        return result

    def process_files_from_worker(self, files_checksums: Dict, decompressed_files_path: str):
        def update_file(n_errors, name, data, file_time=None, content=None, agents=None):
            # Full path
            full_path = common.ossec_path + name
            error_updating_file = False

            # Cluster items information: write mode and umask
            w_mode = cluster_items[data['cluster_item_key']]['write_mode']
            umask = cluster_items[data['cluster_item_key']]['umask']

            if content is None:
                zip_path = "{}/{}".format(decompressed_files_path, name)
                with open(zip_path, 'rb') as f:
                    content = f.read()

            lock_full_path = "{}/queue/cluster/lockdir/{}.lock".format(common.ossec_path, os.path.basename(full_path))
            lock_file = open(lock_full_path, 'a+')
            try:
                fcntl.lockf(lock_file, fcntl.LOCK_EX)
                cluster._update_file(file_path=name, new_content=content,
                             umask_int=umask, mtime=file_time, w_mode=w_mode,
                             tmp_dir=tmp_path, whoami='master', agents=agents)

            except WazuhException as e:
                self.logger.debug2("Warning updating file '{}': {}".format(name, e))
                error_tag = 'warnings'
                error_updating_file = True
            except Exception as e:
                self.logger.debug2("Error updating file '{}': {}".format(name, e))
                error_tag = 'errors'
                error_updating_file = True

            if error_updating_file:
                n_errors[error_tag][data['cluster_item_key']] = 1 if not n_errors[error_tag].get(
                    data['cluster_item_key']) \
                    else n_errors[error_tag][data['cluster_item_key']] + 1

            fcntl.lockf(lock_file, fcntl.LOCK_UN)
            lock_file.close()

            return n_errors, error_updating_file

        # tmp path
        tmp_path = "/queue/cluster/{}/tmp_files".format(self.name)
        cluster_items = cluster.get_cluster_items()['files']
        n_merged_files = 0
        n_errors = {'errors': {}, 'warnings': {}}

        # create temporary directory for lock files
        lock_directory = "{}/queue/cluster/lockdir".format(common.ossec_path)
        if not os.path.exists(lock_directory):
            utils.mkdir_with_mode(lock_directory)

        try:
            agents = Agent.get_agents_overview(select={'fields': ['name']}, limit=None)['items']
            agent_names = set(map(operator.itemgetter('name'), agents))
            agent_ids = set(map(operator.itemgetter('id'), agents))
        except Exception as e:
            self.logger.debug2("Error getting agent ids and names: {}".format(e))
            agent_names, agent_ids = {}, {}

        try:
            for filename, data in files_checksums.items():
                if data['merged']:
                    for file_path, file_data, file_time in cluster.unmerge_agent_info(data['merge_type'],
                                                                                      decompressed_files_path,
                                                                                      data['merge_name']):
                        n_errors, error_updating_file = update_file(n_errors, file_path, data, file_time, file_data,
                                                                    (agent_names, agent_ids))
                        if not error_updating_file:
                            n_merged_files += 1

                    if data['merge_type'] == 'agent-info':
                        self.sync_agent_info_status['total_agent_info'] = n_merged_files
                    else:
                        self.sync_extra_valid_status['total_extra_valid'] = n_merged_files

                else:
                    n_errors, _ = update_file(n_errors, filename, data)

        except Exception as e:
            self.logger.error("Error updating worker files: '{}'.".format(e))
            raise e

        if sum(n_errors['errors'].values()) > 0:
            self.logger.error("Errors updating worker files: {}".format(' | '.join(
                ['{}: {}'.format(key, value) for key, value
                 in n_errors['errors'].items()])
            ))
        if sum(n_errors['warnings'].values()) > 0:
            for key, value in n_errors['warnings'].items():
                if key == '/queue/agent-info/':
                    self.logger.debug2("Received {} agent statuses for non-existent agents. Skipping.".format(value))
                elif key == '/queue/agent-groups/':
                    self.logger.debug2("Received {} group assignments for non-existent agents. Skipping.".format(value))


class Master(server.AbstractServer):

    def __init__(self, **kwargs):
        super().__init__(**kwargs, tag="Master")
        self.integrity_control = {}
        self.tasks.append(self.file_status_update)
        self.handler_class = MasterHandler

    def __dict__(self):
        return {'info': {'name': self.configuration['node_name'], 'type': self.configuration['node_type'],
                'version': metadata.__version__, 'address': self.configuration['nodes'][0]}}

    async def file_status_update(self):
        while True:
            self.logger.debug("Calculating file integrity.")
            try:
                self.integrity_control = cluster.get_files_status('master')
            except Exception as e:
                self.logger.error("Error calculating file integrity: {}".format(e))
            self.logger.debug("File integrity calculated.")

            await asyncio.sleep(30)

    def get_health(self, filter_node) -> Dict:
        """
        Return healthcheck data

        :param filter_node: Node to filter by
        :return: Dictionary
        """
        filter_node = json.loads(filter_node)
        workers_info = {key: val.__dict__() for key, val in self.clients.items() if filter_node is None or key in filter_node}
        n_connected_nodes = len(workers_info) + 1  # all workers + 1 master
        if filter_node is None or self.configuration['node_name'] in filter_node:
            workers_info.update({self.configuration['node_name']: self.__dict__()})

        # Get active agents by node and format last keep alive date format
        for node_name in workers_info.keys():
            workers_info[node_name]["info"]["n_active_agents"] = Agent.get_agents_overview(filters={'status': 'Active', 'node_name': node_name})['totalItems']
            if workers_info[node_name]['info']['type'] != 'master':
                workers_info[node_name]['status']['last_keep_alive'] = str(
                    datetime.fromtimestamp(workers_info[node_name]['status']['last_keep_alive']))

        return {"n_connected_nodes": n_connected_nodes, "nodes": workers_info}
