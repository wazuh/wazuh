# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import asyncio
import json
import random
import re
import shutil
from calendar import timegm
from datetime import datetime
import functools
import operator
import os
from typing import Tuple, Dict, Callable
import fcntl
from wazuh.agent import Agent
from wazuh.cluster import server, cluster, common as c_common
from wazuh import cluster as metadata
from wazuh import common, utils, WazuhException
from wazuh.cluster.dapi import dapi


class ReceiveIntegrityTask(c_common.ReceiveFileTask):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.logger_tag = "Integrity"

    def set_up_coro(self) -> Callable:
        return self.wazuh_common.sync_integrity

    def done_callback(self, future=None):
        super().done_callback(future)
        self.wazuh_common.sync_integrity_free = True


class ReceiveAgentInfoTask(c_common.ReceiveFileTask):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.logger_tag = "Agent info"

    def set_up_coro(self) -> Callable:
        return self.wazuh_common.sync_agent_info

    def done_callback(self, future=None):
        super().done_callback(future)
        self.wazuh_common.sync_agent_info_free = True


class ReceiveExtraValidTask(c_common.ReceiveFileTask):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.logger_tag = "Extra valid"

    def set_up_coro(self) -> Callable:
        return self.wazuh_common.sync_extra_valid

    def done_callback(self, future=None):
        super().done_callback(future)
        self.wazuh_common.sync_extra_valid_free = True


class MasterHandler(server.AbstractServerHandler, c_common.WazuhCommon):

    def __init__(self, **kwargs):
        super().__init__(**kwargs, tag="Worker")
        self.sync_integrity_free = True  # the worker isn't currently synchronizing integrity
        self.sync_extra_valid_free = True
        self.sync_agent_info_free = True
        self.sync_integrity_status = {'date_start_master': "n/a", 'date_end_master': "n/a",
                                      'total_files': {'missing': 0, 'shared': 0, 'extra': 0, 'extra_valid': 0}}
        self.sync_agent_info_status = {'date_start_master': "n/a", 'date_end_master': "n/a",
                                       'total_agentinfo': 0}
        self.sync_extra_valid_status = {'date_start_master': "n/a", 'date_end_master': "n/a",
                                        'total_agentgroups': 0}
        self.version = ""
        self.cluster_name = ""
        self.node_type = ""
        self.task_loggers = {}

    def to_dict(self):
        return {'info': {'name': self.name, 'type': self.node_type, 'version': self.version, 'ip': self.ip},
                'status': {'sync_integrity_free': self.sync_integrity_free, 'last_sync_integrity': self.sync_integrity_status,
                           'sync_agentinfo_free': self.sync_agent_info_free, 'last_sync_agentinfo': self.sync_agent_info_status,
                           'sync_extravalid_free': self.sync_extra_valid_free, 'last_sync_agentgroups': self.sync_extra_valid_status,
                           'last_keep_alive': self.last_keepalive}}

    def process_request(self, command: bytes, data: bytes) -> Tuple[bytes, bytes]:
        self.logger.debug("Command received: {}".format(command))
        if command == b'sync_i_w_m_p' or command == b'sync_e_w_m_p' or command == b'sync_a_w_m_p':
            return self.get_permission(command)
        elif command == b'sync_i_w_m' or command == b'sync_e_w_m' or command == b'sync_a_w_m':
            return self.setup_sync_integrity(command)
        elif command == b'sync_i_w_m_e' or command == b'sync_e_w_m_e' or command == b'sync_a_w_m_e':
            return self.end_receiving_integrity_checksums(data.decode())
        elif command == b'sync_i_w_m_r' or command == b'sync_e_w_m_r' or command == b'sync_a_w_m_r':
            return self.process_sync_error_from_worker(command, data)
        elif command == b'dapi':
            self.server.dapi.add_request(self.name.encode() + b'*' + data)
            return b'ok', b'Added request to API requests queue'
        elif command == b'dapi_res':
            return self.process_dapi_res(data)
        elif command == b'dapi_cluster':
            return self.process_dapi_cluster(data)
        elif command == b'dapi_err':
            dapi_client, error_msg = data.split(b' ', 1)
            asyncio.create_task(self.server.local_server.clients[dapi_client.decode()].send_request(command, error_msg,
                                                                                                    command))
            return b'ok', b'DAPI error forwarded to worker'
        elif command == b'get_nodes':
            cmd, res = self.get_nodes(json.loads(data))
            return cmd, json.dumps(res).encode()
        elif command == b'get_health':
            cmd, res = self.get_health(json.loads(data))
            return cmd, json.dumps(res).encode()
        else:
            return super().process_request(command, data)

    async def execute(self, command: bytes, data: bytes, wait_for_complete: bool) -> str:
        """
        Sends a distributed API request and wait for a response in command dapi_res

        :param command: Command to execute
        :param data: Data to send
        :param wait_for_complete: Raise a timeout exception or not
        :return:
        """
        request_id = str(random.randint(0, 2**10 - 1))
        self.server.pending_api_requests[request_id] = {'Event': asyncio.Event(), 'Response': ''}
        if command == b'dapi_forward':
            client, request = data.split(b' ', 1)
            client = client.decode()
            if client == 'fw_all_nodes':
                for worker in self.server.clients.values():
                    result = (await worker.send_request(b'dapi', request_id.encode() + b' ' + request)).decode()
            elif client in self.server.clients:
                result = (await self.server.clients[client].send_request(b'dapi', request_id.encode() + b' ' + request)).decode()
            else:
                raise WazuhException(3022, client)
        else:
            result = (await self.send_request(b'dapi', request_id.encode() + b' ' + data)).decode()
        if result.startswith('Error'):
            request_result = json.dumps({'error': 3009, 'message': result})
        else:
            if command == b'dapi' or command == b'dapi_forward':
                try:
                    timeout = None if wait_for_complete \
                                   else self.cluster_items['intervals']['communication']['timeout_api_request']
                    await asyncio.wait_for(self.server.pending_api_requests[request_id]['Event'].wait(), timeout=timeout)
                    request_result = self.server.pending_api_requests[request_id]['Response']
                except asyncio.TimeoutError:
                    request_result = json.dumps({'error': 3000, 'message': 'Timeout exceeded'})
            else:
                request_result = result
        return request_result

    def hello(self, data: bytes) -> Tuple[bytes, bytes]:
        name, cluster_name, node_type, version = data.split(b' ')
        cmd, payload = super().hello(name)

        self.task_loggers = {'Integrity': self.setup_task_logger('Integrity'),
                             'Extra valid': self.setup_task_logger('Extra valid'),
                             'Agent info': self.setup_task_logger('Agent info')}

        self.version, self.cluster_name, self.node_type = version.decode(), cluster_name.decode(), node_type.decode()

        if self.cluster_name != self.server.configuration['name']:
            cmd, payload = b'err', b'Worker does not belong to the same cluster'
        elif self.version != metadata.__version__:
            cmd, payload = b'err', b'Worker and master versions are not the same'

        worker_dir = '{}/queue/cluster/{}'.format(common.ossec_path, self.name)
        if cmd == b'ok' and not os.path.exists(worker_dir):
            utils.mkdir_with_mode(worker_dir)
        return cmd, payload

    def get_manager(self):
        return self.server

    def process_dapi_res(self, data: bytes) -> Tuple[bytes, bytes]:
        req_id, string_id = data.split(b' ', 1)
        req_id = req_id.decode()
        if req_id in self.server.pending_api_requests:
            self.server.pending_api_requests[req_id]['Response'] = self.in_str[string_id].payload.decode()
            self.server.pending_api_requests[req_id]['Event'].set()
            return b'ok', b'Forwarded response'
        elif req_id in self.server.local_server.clients:
            asyncio.create_task(self.forward_dapi_response(data))
            return b'ok', b'Response forwarded to worker'
        else:
            self.logger.error("Could not forward request to {}. Connection not available.".format(req_id))
            return b'err', b'Could not forward request, connection is not available'

    def process_dapi_cluster(self, arguments: bytes) -> Tuple[bytes, bytes]:
        api_call_info = json.loads(arguments.decode())
        del api_call_info['arguments']['wait_for_complete']
        if api_call_info['function'] == '/cluster/healthcheck':
            filter_node = None if 'filter_node' not in api_call_info['arguments'] else \
                               [api_call_info['arguments']['filter_node']]
            cmd, res = self.get_health(filter_node)
        else:
            cmd, res = self.get_nodes(api_call_info['arguments'])
            if api_call_info['function'] == '/cluster/nodes/:node_name':
                res = res['items'][0] if len(res['items']) > 0 else {}
        return cmd, json.dumps({'error': 0, 'data': res}).encode()

    def get_nodes(self, arguments: Dict) -> Tuple[bytes, Dict]:
        return b'ok', self.server.get_connected_nodes(**arguments)

    def get_health(self, filter_nodes: Dict) -> Tuple[bytes, Dict]:
        return b'ok', self.server.get_health(filter_nodes)

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
            self.sync_integrity_free, sync_function = False, ReceiveIntegrityTask
        elif sync_type == b'sync_e_w_m':
            self.sync_extra_valid_free, sync_function = False, ReceiveExtraValidTask
        elif sync_type == b'sync_a_w_m':
            self.sync_agent_info_free, sync_function = False, ReceiveAgentInfoTask
        else:
            sync_function = None

        return super().setup_receive_file(sync_function)

    def process_sync_error_from_worker(self, command: bytes, error_msg: bytes) -> Tuple[bytes, bytes]:
        if command == b'sync_i_w_m_r':
            sync_type, self.sync_integrity_free = "Integrity", True
        elif command == b'sync_e_w_m_r':
            sync_type, self.sync_extra_valid_free = "Extra valid", True
        else:  # command == b'sync_a_w_m_r'
            sync_type, self.sync_agent_info_free = "Agent status", True

        self.logger.error("Worker reported an error synchronizing {}: {}".format(sync_type, error_msg.decode()))
        return b'ok', b'Error received'

    def end_receiving_integrity_checksums(self, task_and_file_names: str) -> Tuple[bytes, bytes]:
        return super().end_receiving_file(task_and_file_names)

    async def sync_worker_files(self, task_name: str, received_file: asyncio.Event, logger):
        logger.info("Waiting to receive zip file from worker")
        await asyncio.wait_for(received_file.wait(),
                               timeout=self.cluster_items['intervals']['communication']['timeout_receiving_file'])
        received_filename = self.sync_tasks[task_name].filename
        if received_filename == 'Error':
            logger.info("Stopping synchronization process: worker files weren't correctly received.")
            return

        logger.debug("Received file from worker: '{}'".format(received_filename))

        files_checksums, decompressed_files_path = await cluster.decompress_files(received_filename)
        logger.info("Analyzing worker files: Received {} files to check.".format(len(files_checksums)))
        await self.process_files_from_worker(files_checksums, decompressed_files_path, logger)

    async def sync_extra_valid(self, task_name: str, received_file: asyncio.Event):
        extra_valid_logger = self.task_loggers['Extra valid']
        self.sync_extra_valid_status['date_start_master'] = str(datetime.now())
        await self.sync_worker_files(task_name, received_file, extra_valid_logger)
        self.sync_extra_valid_free = True
        self.sync_extra_valid_status['date_end_master'] = str(datetime.now())

    async def sync_agent_info(self, task_name: str, received_file: asyncio.Event):
        agent_info_logger = self.task_loggers['Agent info']
        self.sync_agent_info_status['date_start_master'] = str(datetime.now())
        await self.sync_worker_files(task_name, received_file, agent_info_logger)
        self.sync_agent_info_free = True
        self.sync_agent_info_status['date_end_master'] = str(datetime.now())

    async def sync_integrity(self, task_name: str, received_file: asyncio.Event):
        logger = self.task_loggers['Integrity']

        self.sync_integrity_status['date_start_master'] = str(datetime.now())

        logger.info("Waiting to receive zip file from worker")
        await asyncio.wait_for(received_file.wait(),
                               timeout=self.cluster_items['intervals']['communication']['timeout_receiving_file'])
        received_filename = self.sync_tasks[task_name].filename
        if received_filename == 'Error':
            logger.info("Stopping synchronization process: worker files weren't correctly received.")
            return
        logger.debug("Received file from worker: '{}'".format(received_filename))

        files_checksums, decompressed_files_path = await cluster.decompress_files(received_filename)
        logger.info("Analyzing worker integrity: Received {} files to check.".format(len(files_checksums)))

        # classify files in shared, missing, extra and extra valid.
        worker_files_ko, counts = cluster.compare_files(self.server.integrity_control, files_checksums, self.name)

        # health check
        self.sync_integrity_status['total_files'] = counts
        shutil.rmtree(decompressed_files_path)

        if not functools.reduce(operator.add, map(len, worker_files_ko.values())):
            logger.info("Analyzing worker integrity: Files checked. There are no KO files.")
            result = await self.send_request(command=b'sync_m_c_ok', data=b'')
        else:
            logger.info("Analyzing worker integrity: Files checked. There are KO files.")

            # Compress data: master files (only KO shared and missing)
            logger.debug("Analyzing worker integrity: Files checked. Compressing KO files.")
            master_files_paths = worker_files_ko['shared'].keys() | worker_files_ko['missing'].keys()
            compressed_data = cluster.compress_files(self.name, master_files_paths, worker_files_ko)

            try:
                logger.info("Analyzing worker integrity: Files checked. KO files compressed.")
                task_name = await self.send_request(command=b'sync_m_c', data=b'')
                if task_name.startswith(b'Error'):
                    logger.error(task_name.decode())
                    return task_name

                result = await self.send_file(compressed_data)
            finally:
                os.unlink(compressed_data)

            if result.startswith(b'Error'):
                self.logger.error("Error sending files information: {}".format(result.decode()))
                result = await self.send_request(command=b'sync_m_c_e', data=task_name + b' ' + b'Error')
            else:
                result = await self.send_request(command=b'sync_m_c_e',
                                                 data=task_name + b' ' + compressed_data.replace(common.ossec_path, '').encode())

            if result.startswith(b'Error'):
                self.logger.error(result.decode())

        self.sync_integrity_status['date_end_master'] = str(datetime.now())
        self.sync_integrity_free = True
        logger.info("Finished integrity synchronization.")
        return result

    async def process_files_from_worker(self, files_checksums: Dict, decompressed_files_path: str, logger):
        async def update_file(name, data):
            # Full path
            full_path, error_updating_file, n_merged_files = common.ossec_path + name, False, 0

            # Cluster items information: write mode and permissions
            lock_full_path = "{}/queue/cluster/lockdir/{}.lock".format(common.ossec_path, os.path.basename(full_path))
            lock_file = open(lock_full_path, 'a+')
            try:
                fcntl.lockf(lock_file, fcntl.LOCK_EX)
                if os.path.basename(name) == 'client.keys':
                    self.logger.warning("Client.keys received in a master node")
                    raise WazuhException(3007)
                if data['merged']:
                    is_agent_info = data['merge_type'] == 'agent-info'
                    if is_agent_info:
                        self.sync_agent_info_status['total_agent_info'] = len(agent_ids)
                    else:
                        self.sync_extra_valid_status['total_extra_valid'] = len(agent_ids)
                    for file_path, file_data, file_time in cluster.unmerge_agent_info(data['merge_type'],
                                                                                      decompressed_files_path,
                                                                                      data['merge_name']):
                        full_unmerged_name = os.path.join(common.ossec_path, file_path)
                        tmp_unmerged_path = os.path.join(common.ossec_path, 'queue/cluster', self.name, os.path.basename(file_path))
                        try:
                            if is_agent_info:
                                agent_name_re = re.match(r'(^.+)-(.+)$', os.path.basename(file_path))
                                agent_name = agent_name_re.group(1) if agent_name_re else os.path.basename(file_path)
                                if agent_name not in agent_names:
                                    n_errors['warnings'][data['cluster_item_key']] = 1 \
                                        if n_errors['warnings'].get(data['cluster_item_key']) is None \
                                        else n_errors['warnings'][data['cluster_item_key']] + 1

                                    self.logger.debug2("Received status of an non-existent agent '{}'".format(agent_name))
                                    continue
                            else:
                                agent_id = os.path.basename(file_path)
                                if agent_id not in agent_ids:
                                    n_errors['warnings'][data['cluster_item_key']] = 1 \
                                        if n_errors['warnings'].get(data['cluster_item_key']) is None \
                                        else n_errors['warnings'][data['cluster_item_key']] + 1

                                    self.logger.debug2("Received group of an non-existent agent '{}'".format(agent_id))
                                    continue

                            try:
                                mtime = datetime.strptime(file_time, '%Y-%m-%d %H:%M:%S.%f')
                            except ValueError:
                                mtime = datetime.strptime(file_time, '%Y-%m-%d %H:%M:%S')

                            if os.path.isfile(full_unmerged_name):

                                local_mtime = datetime.utcfromtimestamp(int(os.stat(full_unmerged_name).st_mtime))
                                # check if the date is older than the manager's date
                                if local_mtime > mtime:
                                    logger.debug2("Receiving an old file ({})".format(file_path))
                                    continue

                            with open(tmp_unmerged_path, 'wb') as f:
                                f.write(file_data)

                            mtime_epoch = timegm(mtime.timetuple())
                            utils.safe_move(tmp_unmerged_path, full_unmerged_name,
                                            ownership=(common.ossec_uid, common.ossec_gid),
                                            permissions=self.cluster_items['files'][data['cluster_item_key']]['permissions'],
                                            time=(mtime_epoch, mtime_epoch)
                                            )
                        except Exception as e:
                            self.logger.error("Error updating agent group/status ({}): {}".format(tmp_unmerged_path, e))
                            if is_agent_info:
                                self.sync_agent_info_status['total_agent_info'] -= 1
                            else:
                                self.sync_extra_valid_status['total_extra_valid'] -= 1

                            n_errors['errors'][data['cluster_item_key']] = 1 \
                                if n_errors['errors'].get(data['cluster_item_key']) is None \
                                else n_errors['errors'][data['cluster_item_key']] + 1
                        await asyncio.sleep(0.0001)

                else:
                    zip_path = "{}{}".format(decompressed_files_path, name)
                    shutil.move(zip_path, full_path, copy_function=shutil.copyfile)
                    try:
                        os.chown(full_path, common.ossec_uid, common.ossec_gid)
                        os.chmod(full_path, self.cluster_items['files'][data['cluster_item_key']]['permissions'])
                    except PermissionError:
                        # We don't care for errors since shutil.move preserve ownership and permissions
                        pass
                    utils.safe_move(zip_path, full_path,
                                    ownership=(common.ossec_uid, common.ossec_gid),
                                    permissions=self.cluster_items['files'][data['cluster_item_key']]['permissions']
                                    )

            except WazuhException as e:
                logger.debug2("Warning updating file '{}': {}".format(name, e))
                error_tag = 'warnings'
                error_updating_file = True
            except Exception as e:
                logger.debug2("Error updating file '{}': {}".format(name, e))
                error_tag = 'errors'
                error_updating_file = True

            if error_updating_file:
                n_errors[error_tag][data['cluster_item_key']] = 1 if not n_errors[error_tag].get(
                    data['cluster_item_key']) \
                    else n_errors[error_tag][data['cluster_item_key']] + 1

            fcntl.lockf(lock_file, fcntl.LOCK_UN)
            lock_file.close()

        # tmp path
        tmp_path = "/queue/cluster/{}/tmp_files".format(self.name)
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
            logger.debug2("Error getting agent ids and names: {}".format(e))
            agent_names, agent_ids = {}, {}

        try:
            for filename, data in files_checksums.items():
                await update_file(data=data, name=filename)

            shutil.rmtree(decompressed_files_path)

        except Exception as e:
            self.logger.error("Error updating worker files: '{}'.".format(e))
            raise e

        if sum(n_errors['errors'].values()) > 0:
            logger.error("Errors updating worker files: {}".format(' | '.join(
                ['{}: {}'.format(key, value) for key, value
                 in n_errors['errors'].items()])
            ))
        if sum(n_errors['warnings'].values()) > 0:
            for key, value in n_errors['warnings'].items():
                if key == '/queue/agent-info/':
                    logger.debug2("Received {} agent statuses for non-existent agents. Skipping.".format(value))
                elif key == '/queue/agent-groups/':
                    logger.debug2("Received {} group assignments for non-existent agents. Skipping.".format(value))

    def get_logger(self, logger_tag: str = ''):
        if logger_tag == '' or logger_tag not in self.task_loggers:
            return self.logger
        else:
            return self.task_loggers[logger_tag]

    def connection_lost(self, exc):
        super().connection_lost(exc)
        # cancel all pending tasks
        self.logger.info("Cancelling pending tasks.")
        for pending_task in self.sync_tasks.values():
            pending_task.task.cancel()


class Master(server.AbstractServer):

    def __init__(self, **kwargs):
        super().__init__(**kwargs, tag="Master")
        self.integrity_control = {}
        self.tasks.append(self.file_status_update)
        self.handler_class = MasterHandler
        self.dapi = dapi.APIRequestQueue(server=self)
        self.tasks.append(self.dapi.run)
        # pending API requests waiting for a response
        self.pending_api_requests = {}

    def to_dict(self):
        return {'info': {'name': self.configuration['node_name'], 'type': self.configuration['node_type'],
                'version': metadata.__version__, 'ip': self.configuration['nodes'][0]}}

    async def file_status_update(self):
        file_integrity_logger = self.setup_task_logger("File integrity")
        while True:
            file_integrity_logger.debug("Calculating")
            try:
                self.integrity_control = cluster.get_files_status('master', self.configuration['node_name'])
            except Exception as e:
                file_integrity_logger.error("Error calculating file integrity: {}".format(e))
            file_integrity_logger.debug("Calculated.")

            await asyncio.sleep(self.cluster_items['intervals']['master']['recalculate_integrity'])

    def get_health(self, filter_node) -> Dict:
        """
        Return healthcheck data

        :param filter_node: Node to filter by
        :return: Dictionary
        """
        workers_info = {key: val.to_dict() for key, val in self.clients.items()
                        if filter_node is None or filter_node == {} or key in filter_node}
        n_connected_nodes = len(workers_info)
        if filter_node is None or self.configuration['node_name'] in filter_node:
            workers_info.update({self.configuration['node_name']: self.to_dict()})

        # Get active agents by node and format last keep alive date format
        for node_name in workers_info.keys():
            workers_info[node_name]["info"]["n_active_agents"] = Agent.get_agents_overview(filters={'status': 'Active', 'node_name': node_name})['totalItems']
            if workers_info[node_name]['info']['type'] != 'master':
                workers_info[node_name]['status']['last_keep_alive'] = str(
                    datetime.fromtimestamp(workers_info[node_name]['status']['last_keep_alive']))

        return {"n_connected_nodes": n_connected_nodes, "nodes": workers_info}

    def get_node(self) -> Dict:
        return {'type': self.configuration['node_type'], 'cluster': self.configuration['name'],
                'node': self.configuration['node_name']}
