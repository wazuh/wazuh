#!/usr/bin/env python

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import ast
import fcntl
import fnmatch
import json
import logging
import os
import shutil
import threading
import time
from datetime import datetime
from operator import itemgetter
from wazuh import common, WazuhException
from wazuh.agent import Agent
from wazuh.cluster import __version__
from wazuh.cluster.cluster import get_cluster_items, _update_file, \
    decompress_files, get_files_status, \
    compress_files, compare_files, read_config, unmerge_agent_info, merge_agent_info, get_cluster_items_master_intervals
from wazuh.cluster.communication import FragmentedStringReceiver, FragmentedFileReceiver, Server, ServerHandler, ClusterThread
from wazuh.cluster.internal_socket import InternalSocketHandler
from wazuh.cluster.dapi import dapi
from wazuh.utils import mkdir_with_mode


logger = logging.getLogger(__name__)

#
# Master Handler
# There is a MasterManagerHandler for each connected worker
#
class MasterManagerHandler(ServerHandler):

    def __init__(self, sock, server, asyncore_map, addr=None):
        ServerHandler.__init__(self, sock, server, asyncore_map, addr)
        self.manager = server

    # Overridden methods
    def process_request(self, command, data):
        logger.debug("[Master ] [{0}] [Request-R    ]: '{1}'.".format(self.name, command))

        if command == 'echo-c':  # Echo
            self.process_keep_alive_from_worker()
            return 'ok-c ', data.decode()
        elif command == 'sync_i_c_m_p':
            result = self.manager.get_worker_status(worker_id=self.name, key='sync_integrity_free')
            return 'ack', str(result)
        elif command == 'sync_ai_c_mp':
            return 'ack', str(self.manager.get_worker_status(worker_id=self.name, key='sync_agentinfo_free'))
        elif command == 'sync_ev_c_mp':
            return 'ack', str(self.manager.get_worker_status(worker_id=self.name, key='sync_extravalid_free'))
        elif command == 'sync_i_c_m':  # Worker syncs integrity
            data = data.decode()
            pci_thread = ProcessWorkerIntegrity(manager=self.manager, manager_handler=self, filename=data, stopper=self.stopper)
            pci_thread.start()
            # data will contain the filename
            return 'ack', self.set_worker_thread(command, pci_thread, data)
        elif command == 'sync_ai_c_m':
            data = data.decode()
            mcf_thread = ProcessWorkerFiles(manager_handler=self, filename=data, stopper=self.stopper)
            mcf_thread.start()
            # data will contain the filename
            return 'ack', self.set_worker_thread(command, mcf_thread, data)
        elif command == 'sync_ev_c_m':
            data = data.decode()
            mcf_thread = ProcessExtraValidFiles(manager_handler=self, filename=data, stopper=self.stopper)
            mcf_thread.start()
            return 'ack', self.set_worker_thread(command, mcf_thread, data)
        elif command == 'get_nodes':
            data = data.decode()
            response = {name:data['info'] for name,data in self.server.get_connected_workers().items()}
            cluster_config = read_config()
            response.update({cluster_config['node_name']:{"name": cluster_config['node_name'], "ip": cluster_config['nodes'][0],  "type": "master",  "version": __version__}})
            serialized_response = ['json', json.dumps(response)]
            return serialized_response
        elif command == 'get_health':
            _, filter_nodes = data.decode().split(' ',1)
            response = self.manager.get_healthcheck(filter_nodes if filter_nodes != 'None' else None)
            serialized_response = ['json', json.dumps(response)]
            return serialized_response
        elif command == 'get_config':
            response = self.manager.get_configuration()
            serialized_response = ['ok', json.dumps(response)]
            return serialized_response
        elif command == 'string':
            string_sender_thread = FragmentedStringReceiverMaster(manager_handler=self, stopper=self.stopper)
            string_sender_thread.start()
            return 'ack', self.set_worker_thread(command, string_sender_thread)
        elif command == 'dapi':
            self.server.add_api_request(self.name + ' ' + data.decode())
            return 'ack', "Request is being processed"
        elif command == "dapi_res":
            string_receiver = FragmentedAPIResponseReceiver(manager_handler=self, stopper=self.stopper, worker_id=data.decode())
            string_receiver.start()
            return 'ack', self.set_worker_thread(command, string_receiver)
        elif command == 'err-is':
            logger.debug("{} Internal socket error received: {}".format(self.tag, data.decode()))
            return 'ack','thanks'
        else:  # Non-master requests
            return ServerHandler.process_request(self, command, data)


    def process_response(self, response):
        # FixMe: Move this line to communications
        answer, payload = self.split_data(response)

        logger.debug("[Master ] [{0}] [Response-R   ]: '{1}'.".format(self.name, answer))

        if answer == 'ok-m':  # test
            response_data = '[response_only_for_master] Worker answered: {}.'.format(payload)
        else:
            response_data = ServerHandler.process_response(self, response)

        return response_data


    # Private methods
    def _update_worker_files_in_master(self, json_file, zip_dir_path, worker_name, cluster_control_key, cluster_control_subkey, tag):
        def update_file(n_errors, name, data, file_time=None, content=None, agents=None):
            # Full path
            full_path = common.ossec_path + name
            error_updating_file = False

            # Cluster items information: write mode and umask
            w_mode = cluster_items[data['cluster_item_key']]['write_mode']
            umask = cluster_items[data['cluster_item_key']]['umask']

            if content is None:
                zip_path = "{}/{}".format(zip_dir_path, name)
                with open(zip_path, 'rb') as f:
                    content = f.read()

            lock_full_path = "{}/queue/cluster/lockdir/{}.lock".format(common.ossec_path, os.path.basename(full_path))
            lock_file = open(lock_full_path, 'a+')
            try:
                fcntl.lockf(lock_file, fcntl.LOCK_EX)
                _update_file(file_path=name, new_content=content,
                             umask_int=umask, mtime=file_time, w_mode=w_mode,
                             tmp_dir=tmp_path, whoami='master', agents=agents)

            except WazuhException as e:
                logger.debug2("{}: Warning updating file '{}': {}".format(tag, name, e))
                error_tag = 'warnings'
                error_updating_file = True
            except Exception as e:
                logger.debug2("{}: Error updating file '{}': {}".format(tag, name, e))
                error_tag = 'errors'
                error_updating_file = True

            if error_updating_file:
                n_errors[error_tag][data['cluster_item_key']] = 1 if not n_errors[error_tag].get(data['cluster_item_key']) \
                                                                  else n_errors[error_tag][data['cluster_item_key']] + 1

            fcntl.lockf(lock_file, fcntl.LOCK_UN)
            lock_file.close()

            return n_errors, error_updating_file


        # tmp path
        tmp_path = "/queue/cluster/{}/tmp_files".format(worker_name)
        cluster_items = get_cluster_items()['files']
        n_merged_files = 0
        n_errors = {'errors': {}, 'warnings': {}}

        # create temporary directory for lock files
        lock_directory = "{}/queue/cluster/lockdir".format(common.ossec_path)
        if not os.path.exists(lock_directory):
            mkdir_with_mode(lock_directory)

        try:
            agents = Agent.get_agents_overview(select={'fields':['name']}, limit=None)['items']
            agent_names = set(map(itemgetter('name'), agents))
            agent_ids = set(map(itemgetter('id'), agents))
        except Exception as e:
            logger.debug2("{}: Error getting agent ids and names: {}".format(tag, e))
            agent_names, agent_ids = {}, {}

        before = time.time()
        try:
            for filename, data in json_file.items():
                if data['merged']:
                    for file_path, file_data, file_time in unmerge_agent_info(data['merge_type'], zip_dir_path, data['merge_name']):
                        n_errors, error_updating_file = update_file(n_errors, file_path, data, file_time, file_data, (agent_names, agent_ids))
                        if not error_updating_file:
                            n_merged_files += 1

                        if self.stopper.is_set():
                            break
                else:
                    n_errors, _ = update_file(n_errors, filename, data)

        except Exception as e:
            logger.error("{}: Error updating worker files: '{}'.".format(tag, e))
            raise e

        after = time.time()
        logger.debug("{0}: Time updating worker files: {1:.2f}s. Total of updated worker files: {2}.".format(tag, after - before, n_merged_files))

        if sum(n_errors['errors'].values()) > 0:
            logging.error("{}: Errors updating worker files: {}".format(tag,
                ' | '.join(['{}: {}'.format(key, value) for key, value in n_errors['errors'].items()])
            ))
        if sum(n_errors['warnings'].values()) > 0:
            for key, value in n_errors['warnings'].items():
                if key == '/queue/agent-info/':
                    logger.debug2("Received {} agent statuses for non-existent agents. Skipping.".format(value))
                elif key == '/queue/agent-groups/':
                    logger.debug2("Received {} group assignments for non-existent agents. Skipping.".format(value))

        # Save info for healthcheck
        self.manager.set_worker_status(worker_id=self.name, key=cluster_control_key, subkey=cluster_control_subkey, status=n_merged_files)


    # New methods
    def process_keep_alive_from_worker(self):
        self.manager.set_worker_status(worker_id=self.name, key='last_keep_alive', status=time.time())


    def process_files_from_worker(self, worker_name, data_received, cluster_control_key, cluster_control_subkey, tag=None):
        sync_result = False

        # Save info for healthcheck
        self.manager.set_worker_status(worker_id=self.name, key=cluster_control_key, subkey="date_start_master", status=datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-4])
        self.manager.set_worker_status(worker_id=self.name, key=cluster_control_key, subkey="date_end_master", status="In progress")
        self.manager.set_worker_status(worker_id=self.name, key=cluster_control_key, subkey=cluster_control_subkey, status="In progress")
        # ---

        if not tag:
            tag = "[Master] [process_files_from_worker]"

        # Extract received data
        logger.info("{0}: Analyzing received files: Start.".format(tag))

        try:
            json_file, zip_dir_path = decompress_files(data_received)
        except Exception as e:
            logger.error("{0}: Error decompressing data: {1}.".format(tag, str(e)))
            raise e

        if json_file:
            worker_files_json = json_file['worker_files']
        else:
            raise Exception("cluster_control.json not included in received zip file")

        logger.info("{0}: Analyzing received files: End.".format(tag))

        logger.info("{0}: Updating master files: Start.".format(tag))

        # Update files
        self._update_worker_files_in_master(worker_files_json, zip_dir_path, worker_name,
                                            cluster_control_key, cluster_control_subkey,
                                            tag)

        # Remove tmp directory created when zip file was received
        shutil.rmtree(zip_dir_path)

        logger.info("{0}: Updating master files: End.".format(tag))

        sync_result = True

        # Save info for healthcheck
        self.manager.set_worker_status(worker_id=self.name, key=cluster_control_key, subkey="date_end_master", status=datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-4])

        return sync_result


    def process_integrity_from_worker(self, worker_name, data_received, cluster_control_key, cluster_control_subkey, tag=None):
        if not tag:
            tag = "[Master] [process_integrity_from_worker]"

        # Extract received data
        logger.info("{0}: Analyzing worker integrity: Start.".format(tag))

        try:
            json_file, zip_dir_path = decompress_files(data_received)
        except Exception as e:
            logger.error("{0}: Error decompressing data: {1}".format(tag, str(e)))
            raise e

        if json_file:
            master_files_from_worker = json_file['master_files']
        else:
            raise Exception("cluster_control.json not included in received zip file")

        logger.info("{0}: Analyzing worker integrity: Received {1} files to check.".format(tag, len(master_files_from_worker)))

        logger.info("{0}: Analyzing worker integrity: Checking files.".format(tag, len(master_files_from_worker)))

        # Get master files
        master_files = self.server.get_integrity_control()

        # Compare
        worker_files_ko = compare_files(master_files, master_files_from_worker)

        agent_groups_to_merge = {key:fnmatch.filter(values.keys(), '*/agent-groups/*')
                                 for key,values in worker_files_ko.items()}
        merged_files = {key:merge_agent_info(merge_type="agent-groups", files=values,
                                         file_type="-"+key, time_limit_seconds=0)
                        for key,values in agent_groups_to_merge.items()}

        for ko, merged in zip(worker_files_ko.items(), agent_groups_to_merge.items()):
            ko_type, ko_files = ko
            if ko_type == "extra" or "extra_valid":
                continue
            _, merged_filenames = merged
            for m in merged_filenames:
                del ko_files[m]
            n_files, merged_file = merged_files[ko_type]
            if n_files > 0:
                ko_files[merged_file] = {'cluster_item_key': '/queue/agent-groups/', 'merged': True}

        # Save info for healthcheck
        self.manager.set_worker_status(worker_id=self.name, key=cluster_control_key, subkey=cluster_control_subkey, subsubkey="missing", status=len(worker_files_ko['missing']))
        self.manager.set_worker_status(worker_id=self.name, key=cluster_control_key, subkey=cluster_control_subkey, subsubkey="shared", status=len(worker_files_ko['shared']))
        self.manager.set_worker_status(worker_id=self.name, key=cluster_control_key, subkey=cluster_control_subkey, subsubkey="extra", status=len(worker_files_ko['extra']))
        self.manager.set_worker_status(worker_id=self.name, key=cluster_control_key, subkey=cluster_control_subkey, subsubkey="extra_valid", status=len(worker_files_ko['extra_valid']))
        # ---

        # Remove tmp directory created when zip file was received
        shutil.rmtree(zip_dir_path)

        # Step 3: KO files
        if len(list(filter(lambda x: x == {}, worker_files_ko.values()))) == len(worker_files_ko):
            logger.info("{0}: Analyzing worker integrity: Files checked. There are no KO files.".format(tag))

            ko_files = False
            data_for_worker = None

        else:
            logger.info("{0}: Analyzing worker integrity: Files checked. There are KO files.".format(tag))

            # Compress data: master files (only KO shared and missing)
            logger.debug("{0} Analyzing worker integrity: Files checked. Compressing KO files.".format(tag))

            master_files_paths = [item for item in worker_files_ko['shared']]
            master_files_paths.extend([item for item in worker_files_ko['missing']])

            compressed_data = compress_files(worker_name, master_files_paths, worker_files_ko)

            logger.debug("{0} Analyzing worker integrity: Files checked. KO files compressed.".format(tag))

            ko_files = True
            data_for_worker = compressed_data

        logger.info("{0}: Analyzing worker integrity: End.".format(tag))

        return ko_files, data_for_worker


#
# Threads (worker_threads) created by MasterManagerHandler
#
class FragmentedStringReceiverMaster(FragmentedStringReceiver):

    def __init__(self, manager_handler, stopper):
        FragmentedStringReceiver.__init__(self, manager_handler, stopper)
        self.thread_tag = "[Master ] [{0}] [String-R     ]".format(self.manager_handler.name)

    def check_connection(self):
        return True


class FragmentedAPIResponseReceiver(FragmentedStringReceiverMaster):

    def __init__(self, manager_handler, stopper, worker_id):
        FragmentedStringReceiverMaster.__init__(self, manager_handler, stopper)
        self.thread_tag = "[Master ] [{}] [API-R_{}]".format(manager_handler.name, worker_id)
        self.worker_id = worker_id

    def process_received_data(self):
        logger.debug("{}: Data received. Forwarding it to local client. ({})".format(self.thread_tag, self.worker_id))

        self.manager_handler.isocket_handler.send_string(self.worker_id, "dapi_res", self.sting_received.decode())
        return True

    def process_cmd(self, command, data):
        requests = {'fwd_new':'new_f_r', 'fwd_upd':'update_f_r', 'fwd_end':'end_f_r'}

        if data is not None and not isinstance(data, bytes):
            data = data.decode()

        return FragmentedStringReceiverMaster.process_cmd(self, requests[command], data)

    def unlock_and_stop(self, reason, send_err_request=None):
        if reason == 'error':
            self.manager_handler.isocket_handler.send_request(self.worker_id, 'err-is', send_err_request)
        FragmentedStringReceiverMaster.unlock_and_stop(self, reason, None)


class ProcessWorker(FragmentedFileReceiver):

    def __init__(self, manager_handler, filename, stopper):
        FragmentedFileReceiver.__init__(self, manager_handler, filename,
                              manager_handler.get_worker(),
                              stopper)

    def check_connection(self):
        return True


    def lock_status(self, status):
        # status_type is used to indicate whether a lock is free or not.
        # if the lock is True, the status should be False because it is not free
        self.manager_handler.manager.set_worker_status(self.name, self.status_type, not status)


    def process_file(self):
        return self.function(self.name, self.filename, self.cluster_control_key, self.cluster_control_subkey, self.thread_tag)


    def unlock_and_stop(self, reason, send_err_request=None):
        logger.info("{0}: Unlocking '{1}' due to {2}.".format(self.thread_tag, self.status_type, reason))
        FragmentedFileReceiver.unlock_and_stop(self, reason, send_err_request)


class ProcessWorkerIntegrity(ProcessWorker):

    def __init__(self, manager, manager_handler, filename, stopper):
        ProcessWorker.__init__(self, manager_handler, filename, stopper)
        self.manager = manager
        self.thread_tag = "[Master ] [{0}] [Integrity-R  ]".format(self.manager_handler.name)
        self.status_type = "sync_integrity_free"
        self.function = self.manager_handler.process_integrity_from_worker
        self.cluster_control_key = "last_sync_integrity"
        self.cluster_control_subkey = "total_files"

    # Overridden methods
    def process_file(self):
        # Save info for healthcheck
        self.manager.set_worker_status(worker_id=self.name, key=self.cluster_control_key, subkey="date_start_master", status=datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-4])
        self.manager.set_worker_status(worker_id=self.name, key=self.cluster_control_key, subkey="date_end_master", status="In progress")
        self.manager.set_worker_status(worker_id=self.name, key=self.cluster_control_key, subkey=self.cluster_control_subkey, subsubkey="missing", status="In progress")
        self.manager.set_worker_status(worker_id=self.name, key=self.cluster_control_key, subkey=self.cluster_control_subkey, subsubkey="shared", status="In progress")
        self.manager.set_worker_status(worker_id=self.name, key=self.cluster_control_key, subkey=self.cluster_control_subkey, subsubkey="extra", status="In progress")
        self.manager.set_worker_status(worker_id=self.name, key=self.cluster_control_key, subkey=self.cluster_control_subkey, subsubkey="extra_valid", status="In progress")
        # ---

        sync_result = False

        ko_files, data_for_worker = self.function(self.name, self.filename, self.cluster_control_key, self.cluster_control_subkey, self.thread_tag)

        if ko_files:
            logger.info("{0}: Sending Sync-KO to worker.".format(self.thread_tag))
            response = self.manager.send_file(self.name, 'sync_m_c', data_for_worker, True)
        else:
            logger.info("{0}: Sending Synk-OK to worker.".format(self.thread_tag))
            response = self.manager.send_request(self.name, 'sync_m_c_ok')

        processed_response = self.manager_handler.process_response(response)

        if processed_response:
            sync_result = True
            logger.info("{0}: Sync accepted by the worker.".format(self.thread_tag))
        else:
            logger.error("{0}: Sync error reported by the worker.".format(self.thread_tag))

        # Save info for healthcheck
        self.manager.set_worker_status(worker_id=self.name, key=self.cluster_control_key, subkey="date_end_master", status=datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-4])

        return sync_result


    def unlock_and_stop(self, reason, send_err_request=True):

        # Send Err
        if send_err_request:
            logger.info("{0}: Sending Sync-Error to worker.".format(self.thread_tag))
            response = self.manager.send_request(self.name, 'sync_m_c_err')

            processed_response = self.manager_handler.process_response(response)

            if processed_response:
                logger.info("{0}: Sync accepted by the worker.".format(self.thread_tag))
            else:
                logger.error("{0}: Sync error reported by the worker.".format(self.thread_tag))

        # Unlock and stop
        ProcessWorker.unlock_and_stop(self, reason)


class ProcessWorkerFiles(ProcessWorker):

   def __init__(self, manager_handler, filename, stopper):
        ProcessWorker.__init__(self, manager_handler, filename, stopper)
        self.thread_tag = "[Master ] [{0}] [AgentInfo-R  ]".format(self.manager_handler.name)
        self.status_type = "sync_agentinfo_free"
        self.function = self.manager_handler.process_files_from_worker
        self.cluster_control_key = "last_sync_agentinfo"
        self.cluster_control_subkey = "total_agentinfo"


class ProcessExtraValidFiles(ProcessWorker):

    def __init__(self, manager_handler, filename, stopper):
        ProcessWorker.__init__(self, manager_handler, filename, stopper)
        self.thread_tag = "[Master ] [{0}] [AgentGroup-R ]".format(self.manager_handler.name)
        self.status_type = "sync_extravalid_free"
        self.function = self.manager_handler.process_files_from_worker
        self.cluster_control_key = "last_sync_agentgroups"
        self.cluster_control_subkey = "total_agentgroups"


#
# Master
#
class MasterManager(Server):
    Integrity_T = "Integrity_Thread"
    APIRequests_T = "API_Requests_Thread"
    ClientStatus_T = "ClientStatusCheck_Thread"

    def __init__(self, cluster_config):
        Server.__init__(self, cluster_config['bind_addr'], cluster_config['port'], MasterManagerHandler)

        logger.info("[Master ] Listening '{0}:{1}'.".format(cluster_config['bind_addr'], cluster_config['port']))

        # Intervals
        self.interval_recalculate_integrity = get_cluster_items_master_intervals()['recalculate_integrity']

        self.config = cluster_config
        self.handler = MasterManagerHandler
        self._integrity_control = {}
        self._integrity_control_lock = threading.Lock()

        # Threads
        self.stopper = threading.Event()  # Event to stop threads
        self.threads = {}
        self._initiate_master_threads()


    # Overridden methods
    def add_worker(self, data, ip, handler):
        worker_id = Server.add_worker(self, data, ip, handler)
        # create directory in /queue/cluster to store all node's file there
        node_path = "{}/queue/cluster/{}".format(common.ossec_path, worker_id)
        if not os.path.exists(node_path):
            mkdir_with_mode(node_path)
        return worker_id


    # Private methods
    def _initiate_master_threads(self):
        logger.debug("[Master ] Creating threads.")

        self.threads[MasterManager.Integrity_T] = FileStatusUpdateThread(master=self, interval=self.interval_recalculate_integrity, stopper=self.stopper)
        self.threads[MasterManager.ClientStatus_T] = ClientStatusCheckThread(master=self, stopper=self.stopper)
        self.threads[MasterManager.APIRequests_T] = dapi.APIRequestQueue(server=self, stopper=self.stopper)

        for thread in self.threads.values():
            thread.start()

        logger.debug("[Master ] Threads created.")

    # New methods
    def set_worker_status(self, worker_id, key, status, subkey=None, subsubkey=None):
        result = False
        with self._workers_lock:
            if worker_id in self._workers:
                if subsubkey:
                    self._workers[worker_id]['status'][key][subkey][subsubkey] = status
                elif subkey:
                    self._workers[worker_id]['status'][key][subkey] = status
                else:
                    self._workers[worker_id]['status'][key] = status
                result = True

        return result


    def get_worker_status(self, worker_id, key):
        result = False

        with self._workers_lock:
            if worker_id in self._workers:
                result = self._workers[worker_id]['status'][key]

        return result

    def get_configuration(self):
        result = False

        if self.config:
            result = self.config

        return result


    def req_file_status_to_workers(self):
        responses = list(self.send_request_broadcast(command = 'file_status'))
        nodes_file = {node:json.loads(data.split(' ',1)[1]) for node,data in responses}
        return 'ok', json.dumps(nodes_file)


    def get_integrity_control(self):
        with self._integrity_control_lock:
            if len(self._integrity_control) == 0:
                raise Exception("Integrity not calculated yet")
            return self._integrity_control


    def set_integrity_control(self, new_integrity_control):
        with self._integrity_control_lock:
            self._integrity_control = new_integrity_control


    def get_healthcheck(self, filter_nodes=None):
        workers_info = {name:{"info":dict(data['info']), "status":data['status'].copy()} for name,data in self.get_connected_workers().items() if not filter_nodes or name in filter_nodes}
        n_connected_nodes = len(workers_info) + 1 # workers + master

        cluster_config = read_config()
        if  not filter_nodes or cluster_config['node_name'] in filter_nodes:
            workers_info.update({cluster_config['node_name']:{"info":{"name": cluster_config['node_name'],
                                                                  "ip": cluster_config['nodes'][0], "version": __version__,
                                                                  "type": "master"}}})

        # Get active agents by node and format last keep alive date format
        for node_name in workers_info.keys():
            workers_info[node_name]["info"]["n_active_agents"]=Agent.get_agents_overview(filters={'status': 'Active', 'node_name': node_name})['totalItems']
            if workers_info[node_name]['info']['type'] != 'master' and isinstance(workers_info[node_name]['status']['last_keep_alive'], float):
                workers_info[node_name]['status']['last_keep_alive'] = str(datetime.fromtimestamp(workers_info[node_name]['status']['last_keep_alive']))

        health_info = {"n_connected_nodes":n_connected_nodes, "nodes": workers_info}
        return health_info


    def exit(self):
        logger.debug("[Master ] Cleaning threads. Start.")

        # Cleaning master threads
        self.stopper.set()

        for thread in self.threads:
            logger.debug2("[Master ] Cleaning threads '{0}'.".format(thread))

            try:
                self.threads[thread].join(timeout=2)
            except Exception as e:
                logger.error("[Master ] Cleaning '{0}' thread. Error: '{1}'.".format(thread, str(e)))

            if self.threads[thread].isAlive():
                logger.warning("[Master ] Cleaning '{0}' thread. Timeout.".format(thread))
            else:
                logger.debug2("[Master ] Cleaning '{0}' thread. Terminated.".format(thread))

        # Cleaning handler threads
        logger.debug("[Master ] Cleaning threads generated to handle workers.")
        workers = self.get_connected_workers().copy().keys()
        for worker in workers:
            self.remove_worker(worker_id=worker)

        logger.debug("[Master ] Cleaning threads. End.")


    def add_api_request(self, request):
        self.threads[self.APIRequests_T].set_request(request)


#
# Master threads
#
class FileStatusUpdateThread(ClusterThread):
    def __init__(self, master, interval, stopper):
        ClusterThread.__init__(self, stopper)
        self.master = master
        self.interval = interval


    def run(self):
        while not self.stopper.is_set() and self.running:
            logger.debug("[Master ] [IntegrityControl] Calculating.")
            try:
                tmp_integrity_control = get_files_status('master')
                self.master.set_integrity_control(tmp_integrity_control)
            except Exception as e:
                logger.error("[Master ] [IntegrityControl] Error: {}".format(str(e)))

            logger.debug("[Master ] [IntegrityControl] Calculated.")

            self.sleep(self.interval)


class ClientStatusCheckThread(ClusterThread):
    def __init__(self, master, stopper):
        ClusterThread.__init__(self, stopper)
        self.master = master
        self.interval = get_cluster_items_master_intervals()['check_worker_lastkeepalive']
        self.thread_tag = "WorkerChecks"


    def run(self):
        while not self.stopper.is_set() and self.running:
            logger.debug("[Master ] [{}] Checking workers statuses.".format(self.thread_tag))

            for worker, worker_info in self.master.get_connected_workers().items():
                if time.time() - worker_info['status']['last_keep_alive'] > get_cluster_items_master_intervals()['max_allowed_time_without_keepalive']:
                    logger.critical("[Master ] [{}] [{}]: Last keep alive is higher than allowed maximum. Disconnecting.".format(self.thread_tag, worker))
                    self.master.remove_worker(worker)

            self.sleep(self.interval)


#
# Internal socket
#
class MasterInternalSocketHandler(InternalSocketHandler):
    def __init__(self, sock, server, asyncore_map, addr):
        InternalSocketHandler.__init__(self, sock=sock, server=server, asyncore_map=asyncore_map, addr=addr)

    def process_request(self, command, data):
        logger.debug("[Master ] [LocalServer  ] Request received in cluster local server: '{0}' - '{1}'".format(command, data))
        data = data.decode()

        if command == 'get_nodes':
            response = {name:data['info'] for name,data in self.server.manager.get_connected_workers().items()}
            cluster_config = read_config()
            response.update({cluster_config['node_name']:{"name": cluster_config['node_name'], "ip": cluster_config['nodes'][0],  "type": "master", "version":__version__}})

            serialized_response = ['json', json.dumps(response)]
            return serialized_response

        elif command == 'get_health':
            _, data = data.split(' ', 1)
            node_list = data if data != 'None' else None
            response = self.server.manager.get_healthcheck(node_list)
            serialized_response = ['json',  json.dumps(response)]
            return serialized_response

        elif command == 'get_config':
            response = self.server.manager.get_configuration()
            serialized_response = ['ok', json.dumps(response)]
            return serialized_response

        elif command == 'dapi':
            return ['json', dapi.distribute_function(json.loads(data.split(' ', 1)[1]))]

        elif command == 'dapi_forward':
            worker_id, node_name, input_json = data.split(' ', 2)
            res_cmd, res = self.server.manager.send_request(worker_name=node_name, command='dapi', data=worker_id + ' ' + input_json).split(' ', 1)
            return res_cmd, res if res_cmd != 'err' else json.dumps({'err': res})

        else:
            return InternalSocketHandler.process_request(self, command, data)
