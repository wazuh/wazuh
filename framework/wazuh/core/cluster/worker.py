# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import asyncio
import errno
import glob
import itertools
import json
import os
import re
import shutil
import time
from typing import Tuple, Dict, Callable, List, TextIO, KeysView

import wazuh.core.cluster.cluster
from wazuh.core import cluster as metadata, common, exception, utils
from wazuh.core.agent import Agent
from wazuh.core.cluster import client, common as c_common
from wazuh.core.cluster import local_client
from wazuh.core.cluster.dapi import dapi
from wazuh.core.database import Connection
from wazuh.core.exception import WazuhClusterError, WazuhInternalError
from wazuh.core.utils import safe_move
from wazuh.core.wdb import WazuhDBConnection


class ReceiveIntegrityTask(c_common.ReceiveFileTask):
    """
    Creates an asyncio.Task that waits until the master sends its integrity information and processes the
    received information.
    """

    def set_up_coro(self) -> Callable:
        """
        Sets up the function to process the integrity files received from master.
        """
        return self.wazuh_common.process_files_from_master


class SyncWorker:
    """
    Define methods to synchronize files with master
    """
    def __init__(self, cmd: bytes, files_to_sync: Dict, checksums: Dict, logger, worker):
        """
        Class constructor

        :param cmd: Request command to send to the master.
        :param files_to_sync: Dictionary containing metadata of the files to send to the master. The keys in this
        dictionary will be iterated to add the files they refer to the zip file that the master will receive.
        :param checksums: Dictionary containing metadata information to send to the master.
        :param logger: Logger to use during synchronization process.
        :param worker: The WorkerHandler object that creates this one.
        """
        self.cmd = cmd
        self.files_to_sync = files_to_sync
        self.checksums = checksums
        self.logger = logger
        self.worker = worker

    async def sync(self):
        """
        Start synchronization process with the master and send necessary information
        """
        result = await self.worker.send_request(command=self.cmd+b'_p', data=b'')
        if isinstance(result, Exception):
            self.logger.error(f"Error asking for permission: {result}")
            return
        elif result == b'True':
            self.logger.info("Permission to synchronize granted")
        else:
            self.logger.info('Master didnt grant permission to synchronize')
            return

        self.logger.info("Compressing files")
        compressed_data_path = wazuh.core.cluster.cluster.compress_files(name=self.worker.name,
                                                                         list_path=self.files_to_sync,
                                                                         cluster_control_json=self.checksums)

        task_id = await self.worker.send_request(command=self.cmd, data=b'')
        try:

            self.logger.info("Sending compressed file to master")
            result = await self.worker.send_file(filename=compressed_data_path)
            self.logger.info("Worker files sent to master")
            result = await self.worker.send_request(command=self.cmd + b'_e',
                                                    data=task_id + b' ' + os.path.relpath(
                                                        compressed_data_path, common.ossec_path).encode())
        except exception.WazuhException as e:
            self.logger.error(f"Error sending files information: {e}")
            result = await self.worker.send_request(command=self.cmd+b'_r',
                                                    data=task_id + b' ' + json.dumps(e, cls=c_common.WazuhJSONEncoder).encode())
        except Exception as e:
            self.logger.error(f"Error sending files information: {e}")
            exc_info = json.dumps(exception.WazuhClusterError(code=1000, extra_message=str(e)),
                                  cls=c_common.WazuhJSONEncoder).encode()
            result = await self.worker.send_request(command=self.cmd+b'_r', data=task_id + b' ' + exc_info)
        finally:
            os.unlink(compressed_data_path)


class RetrieveAndSendToMaster:
    """
    Define methods to send information to self.daemon in the master through sendsync command.
    """

    def __init__(self, worker, destination_daemon, data_retriever: callable, logger=None, msg_format='{payload}',
                 n_retries=3, retry_time=0.2, max_retry_time_allowed=10, cmd=None, expected_res='ok'):
        """Class constructor

        Parameters
        ----------
        worker : WorkerHandler object
            Instance of worker object
        destination_daemon : str
            Daemon name on the master node to which send information.
        cmd : bytes
            Command to inform the master when the synchronization process starts and ends.
        data_retriever : Callable
            Function to be called to obtain chunks of data. It must return a list of chunks.
        logger : Logging object
             Logger to use during synchronization process.
        msg_format : str
            Format of the message to be executed in the master's daemon. It must
            contain the label '{payload}', which will be replaced with every chunk of data.
            I. e: 'global sync-agent-info-set {payload}'
        n_retries : int
            Number of times a chunk has to be resent when it fails.
        retry_time : float
            Time between resend attempts. It is multiplied by the number of retries carried out.
        max_retry_time_allowed : float
            Maximum total time allowed to retry failed requests. If this time has already been
            elapsed, no new attempts will be made to resend all the chunks which response
            does not begin with {expected_res}.
        expected_res : str
            Master's response that will be interpreted as correct. If it doesn't match,
            send retries will be made.
        """
        self.worker = worker
        self.daemon = destination_daemon
        self.msg_format = msg_format
        self.data_retriever = data_retriever
        self.logger = logger if logger is not None else self.worker.setup_task_logger('Default logger')
        self.n_retries = n_retries
        self.retry_time = retry_time
        self.max_retry_time_allowed = max_retry_time_allowed
        self.cmd = cmd
        self.expected_res = expected_res
        self.lc = local_client.LocalClient()

    async def retrieve_and_send(self, *args, **kwargs):
        """Start synchronization process with the master and send necessary information

        This method retrieves a list of payloads/chunks from self.data_retriever(*args, **kwargs).
        The chunks are sent one by one through sendsync command.

        Parameters
        ----------
        *args
            Variable length argument list to be sent as parameter to data_retriever callable
        **kwargs
            Arbitrary keyword arguments to be sent as parameter to data_retriever callable.
        """
        self.logger.info(f"Obtaining data to be sent to master's {self.daemon}.")
        try:
            chunks_to_send = self.data_retriever(*args, **kwargs)
            self.logger.debug(f"Obtained {len(chunks_to_send)} chunks of data to be sent.")
        except exception.WazuhException as e:
            self.logger.error(f"Error obtaining data: {e}")
            return

        if self.cmd:
            # Send command to master so it knows when the task starts
            result = await self.worker.send_request(command=self.cmd + b'_s', data=b'')
            self.logger.debug(f"Master response for {self.cmd+b'_s'} command: {result}")

        chunks_sent = 0
        start_time = time.time()

        self.logger.info(f"Starting to send information to {self.daemon}.")
        for chunk in chunks_to_send:
            data = json.dumps({
                'daemon_name': self.daemon,
                'message': self.msg_format.format(payload=chunk)
            }).encode()

            try:
                # Send chunk of data to self.daemon of the master
                result = await self.lc.execute(command=b'sendasync', data=data, wait_for_complete=False)
                self.logger.debug(f"Master's {self.daemon} response: {result}.")

                # Retry self.n_retries if result was not ok
                if not result.startswith(self.expected_res):
                    for i in range(self.n_retries):
                        if (time.time() - start_time) < self.max_retry_time_allowed:
                            await asyncio.sleep(i * self.retry_time)
                            self.logger.info(f"Error sending chunk to master's {self.daemon}. Response does not start "
                                             f"with {self.expected_res}. Retrying... {i}.")
                            result = await self.lc.execute(command=b'sendasync', data=data, wait_for_complete=False)
                            self.logger.debug(f"Master's {self.daemon} response: {result}.")
                            if result.startswith(self.expected_res):
                                chunks_sent += 1
                                break
                        else:
                            self.logger.info(f"Error sending chunk to master's {self.daemon}. Response does not start "
                                             f"with {self.expected_res}. Not retrying because total time exceeded "
                                             f"{self.max_retry_time_allowed} seconds.")
                            break
                else:
                    chunks_sent += 1

            except exception.WazuhException as e:
                self.logger.error(f"Error sending information to {self.daemon}: {e}")

        if self.cmd:
            # Send command to master so it knows when the task stops
            result = await self.worker.send_request(command=self.cmd + b'_e', data=str(chunks_sent).encode())
            self.logger.debug(f"Master response for {self.cmd+b'_e'} command: {result}")

        self.logger.info(f"Finished sending information to {self.daemon} ({chunks_sent} chunks sent).")


class WorkerHandler(client.AbstractClient, c_common.WazuhCommon):
    """
    Handles connection with the master node
    """

    def __init__(self, version, node_type, cluster_name, **kwargs):
        """
        Class constructor
        :param version: Wazuh version
        :param node_type: Type of node (will always be worker but it's set as a variable in case more types are added
        in the future)
        :param cluster_name: The cluster name
        :param kwargs: Arguments for the parent class constructor
        """
        super().__init__(**kwargs, tag="Worker")
        # the self.client_data will be sent to the master when doing a hello request
        self.client_data = "{} {} {} {}".format(self.name, cluster_name, node_type, version).encode()
        # Every task logger is configured to log using a tag describing the synchronization process. For example,
        # a log coming from the "Integrity" logger will look like this:
        # [Worker name] [Integrity] Bla bla bla
        # this way the same code can be shared among all sync tasks and logs will differentiate.
        self.task_loggers = {'Integrity': self.setup_task_logger('Integrity'),
                             'Extra valid': self.setup_task_logger('Extra valid'),
                             'Agent info': self.setup_task_logger('Agent info')}

    def connection_result(self, future_result):
        """
        Callback function called when the master sends a response to the hello command sent by the worker.
        :param future_result: Result of the hello request
        """
        super().connection_result(future_result)
        if self.connected:
            # create directory for temporary files
            worker_tmp_files = '{}/queue/cluster/{}'.format(common.ossec_path, self.name)
            if not os.path.exists(worker_tmp_files):
                utils.mkdir_with_mode(worker_tmp_files)

    def process_request(self, command: bytes, data: bytes) -> Tuple[bytes, bytes]:
        """
        Defines all commands that a worker can receive from the master
        :param command: Received command
        :param data: Payload received
        :return: A response
        """
        self.logger.debug("Command received: '{}'".format(command))
        if command == b'sync_m_c_ok':
            return self.sync_integrity_ok_from_master()
        elif command == b'sync_m_c':
            return self.setup_receive_files_from_master()
        elif command == b'sync_m_c_e':
            return self.end_receiving_integrity(data.decode())
        elif command == b'sync_m_c_r':
            return self.error_receiving_integrity(data.decode())
        elif command == b'dapi_res':
            asyncio.create_task(self.forward_dapi_response(data))
            return b'ok', b'Response forwarded to worker'
        elif command == b'sendsync_res':
            asyncio.create_task(self.forward_sendsync_response(data))
            return b'ok', b'Response forwarded to worker'
        elif command == b'dapi_err':
            dapi_client, error_msg = data.split(b' ', 1)
            try:
                asyncio.create_task(
                    self.manager.local_server.clients[dapi_client.decode()].send_request(command, error_msg))
            except WazuhClusterError as e:
                raise WazuhClusterError(3025)
            return b'ok', b'DAPI error forwarded to worker'
        elif command == b'sendsync_err':
            sendsync_client, error_msg = data.split(b' ', 1)
            try:
                asyncio.create_task(
                    self.manager.local_server.clients[sendsync_client.decode()].send_request(b'err', error_msg))
            except WazuhClusterError as e:
                raise WazuhClusterError(3025)
            return b'ok', b'SendSync error forwarded to worker'
        elif command == b'dapi':
            self.manager.dapi.add_request(b'master*' + data)
            return b'ok', b'Added request to API requests queue'
        else:
            return super().process_request(command, data)

    def get_manager(self):
        """
        Returns the Worker object that created this WorkerHandler. Used in the class WazuhCommon.
        :return: a Worker object
        """
        return self.manager

    def setup_receive_files_from_master(self):
        """
        Sets up a task to wait until integrity information has been received from the master and process it.
        :return: A confirmation message
        """
        return super().setup_receive_file(ReceiveIntegrityTask)

    def end_receiving_integrity(self, task_and_file_names: str) -> Tuple[bytes, bytes]:
        """
        The master notifies the worker that the integrity has already been sent. The worker notifies the previously
        created task that the information has been received.
        :param task_and_file_names: Task ID and received file name separated by a space (' ')
        :return: A confirmation message
        """
        return super().end_receiving_file(task_and_file_names)

    def error_receiving_integrity(self, taskname_and_error_details: str) -> Tuple[bytes, bytes]:
        return super().error_receiving_file(taskname_and_error_details)

    def sync_integrity_ok_from_master(self) -> Tuple[bytes, bytes]:
        """
        Function called when the master sends the "sync_m_c_ok" command
        :return: confirmation message
        """
        integrity_logger = self.task_loggers['Integrity']
        integrity_logger.info("The master has verified that the integrity is right.")
        return b'ok', b'Thanks'

    async def sync_integrity(self):
        """
        Asynchronous task that is started when the worker connects to the master. It starts an integrity synchronization
        process every self.cluster_items['intervals']['worker']['sync_integrity'] seconds.
        :return: None
        """
        integrity_logger = self.task_loggers["Integrity"]
        while True:
            try:
                if self.connected:
                    before = time.time()
                    await SyncWorker(cmd=b'sync_i_w_m', files_to_sync={}, logger=integrity_logger, worker=self,
                                     checksums=wazuh.core.cluster.cluster.get_files_status('master', self.name)).sync()
                    after = time.time()
                    integrity_logger.debug("Time synchronizing integrity: {} s".format(after - before))
            except exception.WazuhException as e:
                integrity_logger.error("Error synchronizing integrity: {}".format(e))
                res = await self.send_request(command=b'sync_i_w_m_r',
                                              data=json.dumps(e, cls=c_common.WazuhJSONEncoder).encode())
            except Exception as e:
                integrity_logger.error("Error synchronizing integrity: {}".format(e))
                exc_info = json.dumps(exception.WazuhClusterError(code=1000, extra_message=str(e)),
                                      cls=c_common.WazuhJSONEncoder)
                res = await self.send_request(command=b'sync_i_w_m_r', data=exc_info.encode())

            await asyncio.sleep(self.cluster_items['intervals']['worker']['sync_integrity'])

    async def sync_agent_info(self):
        """
        Asynchronous task that is started when the worker connects to the master. It starts an agent-info
        synchronization process every self.cluster_items['intervals']['worker']['sync_files'] seconds.
        :return: None
        """
        agent_info_logger = self.task_loggers["Agent info"]
        wdb_conn = WazuhDBConnection()
        agent_info = RetrieveAndSendToMaster(worker=self, destination_daemon='wazuh-db', logger=agent_info_logger,
                                             msg_format='global sync-agent-info-set {payload}', cmd=b'sync_a_w_m',
                                             data_retriever=wdb_conn.run_wdb_command, max_retry_time_allowed=
                                             self.cluster_items['intervals']['worker']['sync_files'])

        while True:
            try:
                if self.connected:
                    agent_info_logger.info("Starting agent-info sync process.")
                    before = time.time()
                    await agent_info.retrieve_and_send('global sync-agent-info-get ')
                    agent_info_logger.debug2("Time synchronizing agent statuses: {} s".format(time.time() - before))
            except Exception as e:
                agent_info_logger.error("Error synchronizing agent info: {}".format(e))

            await asyncio.sleep(self.cluster_items['intervals']['worker']['sync_files'])

    async def sync_extra_valid(self, extra_valid: Dict):
        """
        Asynchronous task that is started when the master requests any extra valid files to be synchronized.
        That means, it is started in the sync_integrity process.

        :param extra_valid: Files required by the master
        :return: None
        """
        extra_valid_logger = self.task_loggers["Extra valid"]
        try:
            before = time.time()
            self.logger.debug("Starting to send extra valid files")
            # TODO: Add support for more extra valid file types if ever added
            n_files, merged_file = wazuh.core.cluster.cluster.merge_agent_info(merge_type='agent-groups', files=extra_valid.keys(),
                                                                               time_limit_seconds=0, node_name=self.name)
            if n_files:
                files_to_sync = {merged_file: {'merged': True, 'merge_type': 'agent-groups', 'merge_name': merged_file,
                                               'cluster_item_key': '/queue/agent-groups/'}}
                my_worker = SyncWorker(cmd=b'sync_e_w_m', files_to_sync=files_to_sync, checksums=files_to_sync,
                                       logger=extra_valid_logger, worker=self)
                await my_worker.sync()
            after = time.time()
            self.logger.debug2("Time synchronizing extra valid files: {} s".format(after - before))
        except exception.WazuhException as e:
            extra_valid_logger.error("Error synchronizing extra valid files: {}".format(e))
            res = await self.send_request(command=b'sync_e_w_m_r',
                                          data=b'None ' + json.dumps(e, cls=c_common.WazuhJSONEncoder).encode())
        except Exception as e:
            extra_valid_logger.error("Error synchronizing extra valid files: {}".format(e))
            exc_info = json.dumps(exception.WazuhClusterError(code=1000, extra_message=str(e)),
                                  cls=c_common.WazuhJSONEncoder)
            res = await self.send_request(command=b'sync_e_w_m_r', data=b'None ' + exc_info.encode())

    async def process_files_from_master(self, name: str, file_received: asyncio.Event):
        """
        Processes integrity files coming from the master. It updates necessary information and sends the master
        any required extra_valid files.

        :param name: Task name that was waiting for the file to be received
        :param file_received: Asyncio event that is unlocked once the file has been received
        :return: None
        """
        await asyncio.wait_for(file_received.wait(),
                               timeout=self.cluster_items['intervals']['communication']['timeout_receiving_file'])

        if isinstance(self.sync_tasks[name].filename, Exception):
            raise self.sync_tasks[name].filename

        received_filename = self.sync_tasks[name].filename
        try:
            logger = self.task_loggers['Integrity']
            logger.info("Analyzing received files: Start.")

            ko_files, zip_path = await wazuh.core.cluster.cluster.decompress_files(received_filename)
            logger.info("Analyzing received files: Missing: {}. Shared: {}. Extra: {}. ExtraValid: {}".format(
                len(ko_files['missing']), len(ko_files['shared']), len(ko_files['extra']), len(ko_files['extra_valid'])))

            # Update files
            if ko_files['extra_valid']:
                logger.info("Master requires some worker files.")
                asyncio.create_task(self.sync_extra_valid(ko_files['extra_valid']))

            if not ko_files['shared'] and not ko_files['missing'] and not ko_files['extra']:
                logger.info("Worker meets integrity checks. No actions.")
            else:
                logger.info("Worker does not meet integrity checks. Actions required.")
                logger.info("Updating files: Start.")
                self.update_master_files_in_worker(ko_files, zip_path)
                logger.info("Updating files: End.")
        finally:
            shutil.rmtree(zip_path)

    @staticmethod
    def remove_bulk_agents(agent_ids_list: KeysView, logger):
        """
        Removes files created by agents in worker nodes. This function doesn't remove agents from client.keys since the
        client.keys file is overwritten by the master node.
        :param agent_ids_list: List of agents ids to remove.
        :param logger: Logger to use
        :return: None.
        """

        def remove_agent_file_type(agent_files: List[str]):
            """
            Removes files if they exist
            :param agent_files: Path regexes of the files to remove
            :return: None
            """
            for filetype in agent_files:

                filetype_glob = filetype.format(ossec_path=common.ossec_path, id='*', name='*', ip='*')
                filetype_agent = {filetype.format(ossec_path=common.ossec_path, id=a['id'], name=a['name'], ip=a['ip'])
                                  for a in agent_info}

                for agent_file in set(glob.iglob(filetype_glob)) & filetype_agent:
                    logger.debug2("Removing {}".format(agent_file))
                    if os.path.isdir(agent_file):
                        shutil.rmtree(agent_file)
                    else:
                        os.remove(agent_file)

        if not agent_ids_list:
            return  # the function doesn't make sense if there is no agents to remove

        logger.info("Removing files from {} agents".format(len(agent_ids_list)))
        logger.debug("Agents to remove: {}".format(', '.join(agent_ids_list)))
        # Remove agents in group of 500 elements (so wazuh-db socket is not saturated)
        for agents_ids_sublist in itertools.zip_longest(*itertools.repeat(iter(agent_ids_list), 500), fillvalue='0'):
            agents_ids_sublist = list(filter(lambda x: x != '0', agents_ids_sublist))
            # Get info from DB
            agent_info = Agent.get_agents_overview(q=",".join(["id={}".format(i) for i in agents_ids_sublist]),
                                                   select=['ip', 'id', 'name'], limit=None)['items']
            logger.debug2("Removing files from agents {}".format(', '.join(agents_ids_sublist)))

            files_to_remove = ['{ossec_path}/queue/rootcheck/({name}) {ip}->rootcheck',
                               '{ossec_path}/queue/diff/{name}', '{ossec_path}/queue/agent-groups/{id}',
                               '{ossec_path}/queue/rids/{id}',
                               '{ossec_path}/var/db/agents/{name}-{id}.db']
            remove_agent_file_type(files_to_remove)

            logger.debug2("Removing agent group assigments from database")
            # remove agent from groups
            wdb_conn = WazuhDBConnection()

            query_to_execute = 'global sql delete from belongs where {}'.format(' or '.join([
                'id_agent = {}'.format(agent_id) for agent_id in agents_ids_sublist
            ]))
            wdb_conn.run_wdb_command(query_to_execute)

        logger.info("Agent files removed")

    @staticmethod
    def _check_removed_agents(new_client_keys_path: str, logger):
        """
        Function to delete agents that have been deleted in a synchronized
        client.keys.

        It makes a diff of the old client keys and the new one and search for
        deleted or changed lines (in the diff those lines start with -).

        If a line starting with - matches the regex structure of a client.keys line
        that agent is deleted.
        """

        def parse_client_keys(client_keys_contents: TextIO):
            """
            Parses client.keys file into a dictionary
            :param client_keys_contents: client.keys file object
            :return: generator of dictionaries.
            """
            ck_line = re.compile(r'\d+ \S+ \S+ \S+')
            return {a_id: {'name': a_name, 'ip': a_ip, 'key': a_key} for a_id, a_name, a_ip, a_key in
                    map(lambda x: x.split(' '), filter(lambda x: ck_line.match(x) is not None, client_keys_contents))
                    if not a_name.startswith('!')}

        ck_path = "{0}/etc/client.keys".format(common.ossec_path)
        try:
            with open(ck_path) as ck:
                # can't use readlines function since it leaves a \n at the end of each item of the list
                client_keys_dict = parse_client_keys(ck)
        except Exception as e:
            # if client.keys can't be read, it can't be parsed
            logger.warning("Could not parse client.keys file: {}".format(e))
            return

        with open(new_client_keys_path) as n_ck:
            new_client_keys_dict = parse_client_keys(n_ck)

        # get removed agents: the ones missing in the new client keys and present in the old
        try:
            WorkerHandler.remove_bulk_agents(client_keys_dict.keys() - new_client_keys_dict.keys(), logger)
        except Exception as e:
            logger.error("Error removing agent files: {}".format(e))
            raise e

    def update_master_files_in_worker(self, ko_files: Dict, zip_path: str):
        """
        Iterates over received files and updates them locally.
        :param ko_files: File metadata coming from the master
        :param zip_path: Pathname of the received zip file containing the files to update
        :return: None
        """
        def overwrite_or_create_files(filename: str, data: Dict):
            """
            Updates a file coming from the master
            :param filename: Filename to update
            :param data: File metadata such as modification time, whether it's a merged file or not, etc.
            :return: None
            """
            full_filename_path = common.ossec_path + filename
            if os.path.basename(filename) == 'client.keys':
                self._check_removed_agents("{}{}".format(zip_path, filename), logger)

            if data['merged']:  # worker nodes can only receive agent-groups files
                if data['merge-type'] == 'agent-info':
                    logger.warning("Agent status received in a worker node")
                    raise WazuhInternalError(3011)

                for name, content, _ in wazuh.core.cluster.cluster.unmerge_agent_info('agent-groups', zip_path, filename):
                    full_unmerged_name = os.path.join(common.ossec_path, name)
                    tmp_unmerged_path = full_unmerged_name + '.tmp'
                    with open(tmp_unmerged_path, 'wb') as f:
                        f.write(content)
                    safe_move(tmp_unmerged_path, full_unmerged_name,
                              permissions=self.cluster_items['files'][data['cluster_item_key']]['permissions'],
                              ownership=(common.ossec_uid(), common.ossec_gid())
                              )
            else:
                if not os.path.exists(os.path.dirname(full_filename_path)):
                    utils.mkdir_with_mode(os.path.dirname(full_filename_path))
                safe_move("{}{}".format(zip_path, filename), full_filename_path,
                          permissions=self.cluster_items['files'][data['cluster_item_key']]['permissions'],
                          ownership=(common.ossec_uid(), common.ossec_gid())
                          )

        logger = self.task_loggers['Integrity']
        errors = {'shared': 0, 'missing': 0, 'extra': 0}
        for filetype, files in ko_files.items():
            if filetype == 'shared' or filetype == 'missing':
                logger.debug("Received {} {} files to update from master.".format(len(ko_files[filetype]),
                                                                                  filetype))
                for filename, data in files.items():
                    try:
                        logger.debug2("Processing file {}".format(filename))
                        overwrite_or_create_files(filename, data)
                    except Exception as e:
                        errors[filetype] += 1
                        logger.error("Error processing {} file '{}': {}".format(filetype, filename, e))
                        continue
            elif filetype == 'extra':
                for file_to_remove in files:
                    try:
                        logger.debug2("Remove file: '{}'".format(file_to_remove))
                        file_path = common.ossec_path + file_to_remove
                        try:
                            os.remove(file_path)
                        except OSError as e:
                            if e.errno == errno.ENOENT and '/queue/agent-groups/' in file_path:
                                logger.debug2("File {} doesn't exist.".format(file_to_remove))
                                continue
                            else:
                                raise e
                    except Exception as e:
                        errors['extra'] += 1
                        logger.debug2("Error removing file '{}': {}".format(file_to_remove, e))
                        continue

        directories_to_check = (os.path.dirname(f) for f, data in ko_files['extra'].items()
                                if self.cluster_items['files'][data['cluster_item_key']]['remove_subdirs_if_empty'])
        for directory in directories_to_check:
            try:
                full_path = common.ossec_path + directory
                dir_files = set(os.listdir(full_path))
                if not dir_files or dir_files.issubset(set(self.cluster_items['files']['excluded_files'])):
                    shutil.rmtree(full_path)
            except Exception as e:
                errors['extra'] += 1
                logger.debug2("Error removing directory '{}': {}".format(directory, e))
                continue

        if sum(errors.values()) > 0:
            logger.error("Found errors: {} overwriting, {} creating and {} removing".format(errors['shared'],
                                                                                            errors['missing'],
                                                                                            errors['extra']))

    def get_logger(self, logger_tag: str = ''):
        """
        Returns the current logger. This method is used in WazuhCommon class.
        :param logger_tag: Logger tag to return. In workers it will always return the main logger.
        :return: A logger object
        """
        return self.logger


class Worker(client.AbstractClientManager):
    """
    Initializes worker variables, connects to the master and runs the DAPI request queue.
    """

    def __init__(self, **kwargs):
        """
        Class constructor
        :param kwargs: Arguments for the parent class
        """
        super().__init__(**kwargs, tag="Worker")
        self.cluster_name = self.configuration['name']
        self.version = metadata.__version__
        self.node_type = self.configuration['node_type']
        self.handler_class = WorkerHandler
        self.extra_args = {'cluster_name': self.cluster_name, 'version': self.version, 'node_type': self.node_type}
        self.dapi = dapi.APIRequestQueue(server=self)

    def add_tasks(self) -> List[Tuple[asyncio.coroutine, Tuple]]:
        """
        Defines the tasks the worker will always run in a infinite loop.
        :return: A list of tuples: The first item is the coroutine to run and the second is the arguments it needs.
        In this case, all coroutines dont't need any arguments.
        """
        return super().add_tasks() + [(self.client.sync_integrity, tuple()), (self.client.sync_agent_info, tuple()),
                                      (self.dapi.run, tuple())]

    def get_node(self) -> Dict:
        """
        Returns basic information about the worker node. Used in the GET/cluster/node API call
        :return: A dictionary with basic node information
        """
        return {'type': self.configuration['node_type'], 'cluster': self.configuration['name'],
                'node': self.configuration['node_name']}
