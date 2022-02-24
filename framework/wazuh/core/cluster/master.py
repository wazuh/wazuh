# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import asyncio
import functools
import json
import operator
import os
import shutil
from calendar import timegm
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime
from time import perf_counter
from typing import Tuple, Dict, Callable
from uuid import uuid4

import wazuh.core.cluster.cluster
from wazuh.core import cluster as metadata, common, exception, utils
from wazuh.core.agent import Agent
from wazuh.core.cluster import server, cluster, common as c_common
from wazuh.core.cluster.dapi import dapi
from wazuh.core.cluster.utils import context_tag
from wazuh.core.common import decimals_date_format
from wazuh.core.wdb import WazuhDBConnection


class ReceiveIntegrityTask(c_common.ReceiveFileTask):
    """
    Define the process and variables necessary to receive and process integrity information from the master.

    This task is created by the master when the worker starts sending its integrity file metadata and it's destroyed
    by the master once the necessary files to update have been sent.
    """

    def __init__(self, *args, **kwargs):
        """Class constructor.

        Parameters
        ----------
        args
            Positional arguments for parent constructor class.
        kwargs
            Keyword arguments for parent constructor class.
        """
        super().__init__(*args, **kwargs)

    def set_up_coro(self) -> Callable:
        """Set up the function to be called when the worker sends its integrity information."""
        return self.wazuh_common.sync_integrity

    def done_callback(self, future=None):
        """Check whether the synchronization process was correct and free its lock.

        Parameters
        ----------
        future : asyncio.Future object
            Synchronization process result.
        """
        super().done_callback(future)
        # Integrity task is only freed if master is not waiting for Extra valid files.
        if not self.wazuh_common.extra_valid_requested:
            self.wazuh_common.sync_integrity_free[0] = True


class ReceiveExtraValidTask(c_common.ReceiveFileTask):
    """
    Define the process and variables necessary to receive and process extra valid files from the worker.

    This task is created when the worker starts sending extra valid files and its destroyed once the master has updated
    all the required information.
    """

    def __init__(self, *args, **kwargs):
        """Class constructor.

        Parameters
        ----------
        args
            Positional arguments for parent constructor class.
        kwargs
            Keyword arguments for parent constructor class.
        """
        super().__init__(*args, **kwargs)

    def set_up_coro(self) -> Callable:
        """Set up the function to be called when the worker sends the previously required extra valid files."""
        return self.wazuh_common.sync_extra_valid

    def done_callback(self, future=None):
        """Check whether the synchronization process was correct and free its lock.

        Parameters
        ----------
        future : asyncio.Future object
            Synchronization process result.
        """
        super().done_callback(future)
        self.wazuh_common.extra_valid_requested = False
        self.wazuh_common.sync_integrity_free[0] = True


class ReceiveAgentInfoTask(c_common.ReceiveStringTask):
    """
    Define the process and variables necessary to receive and process Agent info from the worker.

    This task is created when the worker finishes sending Agent info chunks and its destroyed once the master has
    updated all the received information.
    """

    def __init__(self, *args, **kwargs):
        """Class constructor.

        Parameters
        ----------
        args
            Positional arguments for parent constructor class.
        kwargs
            Keyword arguments for parent constructor class.
        """
        super().__init__(*args, **kwargs, info_type='agent-info')

    def set_up_coro(self) -> Callable:
        """Set up the function to be called when the worker sends its Agent info."""
        return self.wazuh_common.setup_sync_wazuh_db_information

    def done_callback(self, future=None):
        """Check whether the synchronization process was correct and free its lock.

        Parameters
        ----------
        future : asyncio.Future object
            Synchronization process result.
        """
        super().done_callback(future)
        self.wazuh_common.sync_agent_info_free = True


class ReceiveAgentGroupsTask(c_common.ReceiveStringTask):
    """
    Define the process and variables necessary to receive and process agent-groups from the worker.

    This task is created when the worker finishes sending agent-groups chunks and its destroyed once the master has
    updated all the received information.
    """

    def __init__(self, *args, **kwargs):
        """Class constructor.

        Parameters
        ----------
        args
            Positional arguments for parent constructor class.
        kwargs
            Keyword arguments for parent constructor class.
        """
        super().__init__(*args, **kwargs, info_type='agent-groups')

    def set_up_coro(self) -> Callable:
        """Set up the function to be called when the worker sends its agent-groups."""
        return self.wazuh_common.setup_sync_wazuh_db_information

    def done_callback(self, future=None):
        """Check whether the synchronization process was correct and free its lock.

        Parameters
        ----------
        future : asyncio.Future object
            Synchronization process result.
        """
        super().done_callback(future)
        self.wazuh_common.sync_agent_groups_free = True


class SendEntireAgentGroupsTask(c_common.SendStringTask):
    """
    Define the process and variables necessary to send the entire agent-groups from the master to the worker.

    This task is created when the worker needs the entire agent-groups information.
    """

    def __init__(self, *args, **kwargs):
        """Class constructor.

        Parameters
        ----------
        args
            Positional arguments for parent constructor class.
        kwargs
            Keyword arguments for parent constructor class.
        """
        super().__init__(*args, **kwargs)

    def set_up_coro(self) -> Callable:
        """Set up the function to be called when the worker needs the entire agent-groups information."""
        return self.wazuh_common.send_entire_agent_groups_information


class MasterHandler(server.AbstractServerHandler, c_common.WazuhCommon):
    """
    Handle incoming requests and sync processes with a worker.
    """

    def __init__(self, **kwargs):
        """Class constructor.

        Parameters
        ----------
        kwargs
            Arguments for the parent class constructor.
        """
        super().__init__(**kwargs, tag="Worker")
        # Sync availability variables. Used to prevent sync process from overlapping.
        self.sync_agent_info_free = True
        self.sync_agent_groups_free = True
        self.sync_integrity_free = [True, datetime.utcnow()]

        # Variable used to check whether integrity sync process includes extra_valid files.
        self.extra_valid_requested = False

        # Sync status variables. Used in cluster_control -i and GET/cluster/healthcheck.
        default_date = datetime.utcfromtimestamp(0)
        self.integrity_check_status = {'date_start_master': default_date, 'date_end_master': default_date}
        self.integrity_sync_status = {'date_start_master': default_date, 'tmp_date_start_master': default_date,
                                      'date_end_master': default_date, 'total_extra_valid': 0,
                                      'total_files': {'missing': 0, 'shared': 0, 'extra': 0, 'extra_valid': 0}}
        self.sync_agent_info_status = {'date_start_master': default_date, 'date_end_master': default_date,
                                       'n_synced_chunks': 0}
        self.sync_agent_groups_status = {'date_start_master': default_date, 'date_end_master': default_date,
                                         'n_synced_chunks': 0}
        self.send_agent_groups_status = {'date_start': 0.0}

        # Variables which will be filled when the worker sends the hello request.
        self.version = ""
        self.cluster_name = ""
        self.node_type = ""
        # Dictionary to save loggers for each sync task.
        self.task_loggers = {}
        context_tag.set(self.tag)

    def to_dict(self):
        """Get worker healthcheck information.

        Returns
        -------
        dict
            Healthcheck information for each process.
        """
        return {'info': {'name': self.name, 'type': self.node_type, 'version': self.version, 'ip': self.ip},
                'status': {'sync_integrity_free': self.sync_integrity_free[0],
                           'last_check_integrity': {key: value for key, value in self.integrity_check_status.items() if
                                                    not key.startswith('tmp')},
                           'last_sync_integrity': {key: value for key, value in self.integrity_sync_status.items() if
                                                   not key.startswith('tmp')},
                           'sync_agent_info_free': self.sync_agent_info_free,
                           'sync_agent_groups_free': self.sync_agent_groups_free,
                           'last_sync_agentinfo': self.sync_agent_info_status,
                           'last_sync_agentgroups': self.sync_agent_groups_status,
                           'last_keep_alive': self.last_keepalive}
                }

    def process_request(self, command: bytes, data: bytes) -> Tuple[bytes, bytes]:
        """Define all available commands that can be received from a worker node.

        Parameters
        ----------
        command : bytes
            Received command.
        data : bytes
            Received payload.

        Returns
        -------
        bytes
            Result.
        bytes
            Response message.
        """
        self.logger.debug(f"Command received: {command}")
        if command == b'syn_i_w_m_p' or command == b'syn_a_w_m_p' or command == b'syn_g_w_m_p':
            return self.get_permission(command)
        elif command == b'syn_i_w_m' or command == b'syn_e_w_m' or command == b'syn_a_w_m' or command == b'syn_g_w_m':
            return self.setup_sync_integrity(command, data)
        elif command == b'syn_w_g_c':
            return self.setup_send_info(command)
        elif command == b'syn_i_w_m_e' or command == b'syn_e_w_m_e':
            return self.end_receiving_integrity_checksums(data.decode())
        elif command == b'syn_i_w_m_r':
            return self.process_sync_error_from_worker(data)
        elif command == b'syn_w_g_e':
            logger = self.task_loggers['Agent-groups send']
            start_time = self.send_agent_groups_status['date_start']
            return c_common.end_sending_agent_information(logger, start_time, data.decode())
        elif command == b'syn_w_g_err':
            logger = self.task_loggers['Agent-groups send']
            return c_common.error_receiving_agent_information(logger, data.decode(), info_type='agent-groups')
        elif command == b'dapi':
            self.server.dapi.add_request(self.name.encode() + b'*' + data)
            return b'ok', b'Added request to API requests queue'
        elif command == b'dapi_res':
            return self.process_dapi_res(data)
        elif command == b'dapi_err':
            dapi_client, error_msg = data.split(b' ', 1)
            asyncio.create_task(
                self.server.local_server.clients[dapi_client.decode()].send_request(command, error_msg))
            return b'ok', b'DAPI error forwarded to worker'
        elif command == b'get_nodes':
            cmd, res = self.get_nodes(json.loads(data))
            return cmd, json.dumps(res).encode()
        elif command == b'get_health':
            cmd, res = self.get_health(json.loads(data))
            return cmd, json.dumps(res,
                                   default=lambda o: "n/a" if isinstance(o,
                                                                         datetime) and o == datetime.utcfromtimestamp(0)
                                   else (o.__str__() if isinstance(o, datetime) else None)
                                   ).encode()
        elif command == b'sendsync':
            self.server.sendsync.add_request(self.name.encode() + b'*' + data)
            return b'ok', b'Added request to SendSync requests queue'
        else:
            return super().process_request(command, data)

    async def execute(self, command: bytes, data: bytes, wait_for_complete: bool) -> Dict:
        """Send DAPI request and wait for response.

        Send a distributed API request and wait for a response in command dapi_res. Methods here are the same
        as the ones defined in LocalServerHandlerMaster.

        Parameters
        ----------
        command : bytes
            Command to execute.
        data : bytes
            Data to send.
        wait_for_complete : bool
            Whether to raise a timeout exception or not.

        Returns
        -------
        request_result : dict
            API response.
        """
        request_id = str(uuid4())
        # Create an event to wait for the response.
        self.server.pending_api_requests[request_id] = {'Event': asyncio.Event(), 'Response': ''}

        # If forward request to other worker, get destination client and request.
        if command == b'dapi_fwd':
            client, request = data.split(b' ', 1)
            client = client.decode()
            if client in self.server.clients:
                result = (await self.server.clients[client].send_request(b'dapi',
                                                                         request_id.encode() + b' ' + request)).decode()
            else:
                raise exception.WazuhClusterError(3022, extra_message=client)
        # Add request to local API requests queue.
        elif command == b'dapi':
            result = (await self.send_request(b'dapi', request_id.encode() + b' ' + data)).decode()
        # If not dapi related command, run it now.
        else:
            result = self.process_request(command=command, data=data)

        # If command was dapi or dapi_fwd, wait for response.
        if command == b'dapi' or command == b'dapi_fwd':
            try:
                timeout = None if wait_for_complete \
                    else self.cluster_items['intervals']['communication']['timeout_dapi_request']
                await asyncio.wait_for(self.server.pending_api_requests[request_id]['Event'].wait(), timeout=timeout)
                request_result = self.server.pending_api_requests[request_id]['Response']
            except asyncio.TimeoutError:
                raise exception.WazuhClusterError(3021)
        # Otherwise, immediately return the result obtained before.
        else:
            status, request_result = result
            if status != b'ok':
                raise exception.WazuhClusterError(3022, extra_message=request_result.decode())
            request_result = request_result.decode()
        return request_result

    def hello(self, data: bytes) -> Tuple[bytes, bytes]:
        """Process 'hello' command from worker.

        Process 'hello' command sent by a worker right after it connects to the server. It also initializes
        the task loggers.

        Parameters
        ----------
        data : bytes
            Node name, cluster name, node type and wazuh version all separated by spaces.

        Returns
        -------
        cmd : bytes
            Result.
        payload : bytes
            Response message.
        """
        name, cluster_name, node_type, version = data.split(b' ')
        # Add client to global clients dictionary.
        cmd, payload = super().hello(name)

        self.task_loggers = {'Integrity check': self.setup_task_logger('Integrity check'),
                             'Integrity sync': self.setup_task_logger('Integrity sync'),
                             'Agent-info sync': self.setup_task_logger('Agent-info sync'),
                             'Agent-groups sync': self.setup_task_logger('Agent-groups sync'),
                             'Agent-groups send': self.setup_task_logger('Agent-groups send'),
                             'Agent-groups full DB': self.setup_task_logger('Agent-groups full DB')}

        # Fill more information and check both name and version are correct.
        self.version, self.cluster_name, self.node_type = version.decode(), cluster_name.decode(), node_type.decode()

        if self.cluster_name != self.server.configuration['name']:
            raise exception.WazuhClusterError(3030)
        elif self.version != metadata.__version__:
            raise exception.WazuhClusterError(3031)

        # Create directory where zips and other files coming from or going to the worker will be managed.
        worker_dir = os.path.join(common.wazuh_path, 'queue', 'cluster', self.name)
        if cmd == b'ok' and not os.path.exists(worker_dir):
            utils.mkdir_with_mode(worker_dir)

        # Initialize agent-groups sending task
        asyncio.ensure_future(self.send_agent_groups_information())

        return cmd, payload

    def get_manager(self) -> server.AbstractServer:
        """Get the Master object that created this MasterHandler. Used in the class WazuhCommon.

        Returns
        -------
        AbstractServer
            Master object.
        """
        return self.server

    def process_dapi_res(self, data: bytes) -> Tuple[bytes, bytes]:
        """Process a DAPI response coming from a worker node.

        This function is called when the master received a "dapi_res" command. The response
        has been previously sent using a send_string so this method only receives the string ID.

        If the request ID is within the pending api requests, the response is assigned to the request ID and
        the server is notified. Else, if the request ID is within the local_server clients, it is forwarded.

        Parameters
        ----------
        data : bytes
            Request ID and response ID separated by a space (' ').

        Returns
        -------
        bytes
            Result.
        bytes
            Response message.
        """
        req_id, string_id = data.split(b' ', 1)
        req_id = req_id.decode()
        if req_id in self.server.pending_api_requests:
            self.server.pending_api_requests[req_id]['Response'] = self.in_str[string_id].payload.decode()
            self.server.pending_api_requests[req_id]['Event'].set()
            # Remove the string after using it
            self.in_str.pop(string_id, None)
            return b'ok', b'Forwarded response'
        elif req_id in self.server.local_server.clients:
            asyncio.create_task(self.forward_dapi_response(data))
            return b'ok', b'Response forwarded to worker'
        else:
            raise exception.WazuhClusterError(3032, extra_message=req_id)

    def get_nodes(self, arguments: Dict) -> Tuple[bytes, Dict]:
        """Process 'get_nodes' request.

        Parameters
        ----------
        arguments : dict
            Arguments to use in get_connected_nodes function (filter, sort, etc).

        Returns
        -------
        bytes
            Result.
        dict
            Dict object containing nodes information.
        """
        return b'ok', self.server.get_connected_nodes(**arguments)

    def get_health(self, filter_nodes: Dict) -> Tuple[bytes, Dict]:
        """Process 'get_health' request.

        Parameters
        ----------
        filter_nodes : dict
            Whether to filter by a node or return all health information.

        Returns
        -------
        bytes
            Result.
        dict
            Dict object containing nodes information.
        """
        return b'ok', self.server.get_health(filter_nodes)

    def get_permission(self, sync_type: bytes) -> Tuple[bytes, bytes]:
        """Get whether a sync process is in progress or not.

        Parameters
        ----------
        sync_type : bytes
            Sync process to check.

        Returns
        -------
        bytes
            Result.
        bytes
            Response message.
        """
        # Check if an integrity_check has already been performed
        # for the worker in the current iteration of local_integrity
        if sync_type == b'syn_i_w_m_p' and self.name not in self.server.integrity_already_executed:
            # Add the variable self.name to keep track of the number of integrity_checks per cycle
            self.server.integrity_already_executed.append(self.name)

            # Reset integrity permissions if False for more than "max_locked_integrity_time" seconds
            if not self.sync_integrity_free[0] and (datetime.utcnow() - self.sync_integrity_free[1]).total_seconds() > \
                    self.cluster_items['intervals']['master']['max_locked_integrity_time']:
                self.logger.warning(f'Automatically releasing Integrity check permissions flag ({sync_type}) after '
                                    f'being locked out for more than '
                                    f'{self.cluster_items["intervals"]["master"]["max_locked_integrity_time"]}s.')
                self.sync_integrity_free[0] = True

            permission = self.sync_integrity_free[0]
        elif sync_type == b'syn_a_w_m_p':
            permission = self.sync_agent_info_free
        elif sync_type == b'syn_g_w_m_p':
            permission = self.sync_agent_groups_free
        else:
            permission = False

        return b'ok', str(permission).encode()

    def setup_sync_integrity(self, sync_type: bytes, data: bytes = None) -> Tuple[bytes, bytes]:
        """Start synchronization process.

        Parameters
        ----------
        sync_type : bytes
            Sync process to start.
        data : bytes
            Data to be sent.

        Returns
        -------
        bytes
            Result.
        bytes
            Response message.
        """
        if sync_type == b'syn_i_w_m':
            self.sync_integrity_free, sync_function = [False, datetime.utcnow()], ReceiveIntegrityTask
        elif sync_type == b'syn_e_w_m':
            sync_function = ReceiveExtraValidTask
        elif sync_type == b'syn_a_w_m':
            self.sync_agent_info_free, sync_function = False, ReceiveAgentInfoTask
        elif sync_type == b'syn_g_w_m':
            self.sync_agent_groups_free, sync_function = False, ReceiveAgentGroupsTask
        else:
            sync_function = None

        return super().setup_receive_file(sync_function, data)

    def setup_send_info(self, sync_type: bytes) -> Tuple[bytes, bytes]:
        """Start synchronization process.

        Parameters
        ----------
        sync_type : bytes
            Sync process to start.

        Returns
        -------
        bytes
            Result.
        bytes
            Response message.
        """
        if sync_type == b'syn_w_g_c':
            sync_function = SendEntireAgentGroupsTask
        else:
            sync_function = None

        return super().setup_send_info(sync_function)

    def process_sync_error_from_worker(self, error_msg: bytes) -> Tuple[bytes, bytes]:
        """Manage error during synchronization process reported by a worker.

        Mark the process as free so a new one can start.

        Parameters
        ----------
        error_msg : bytes
            Error information.

        Returns
        -------
        bytes
            Result.
        bytes
            Response message.
        """
        self.sync_integrity_free[0] = True
        return super().error_receiving_file(error_msg.decode())

    def end_receiving_integrity_checksums(self, task_and_file_names: str) -> Tuple[bytes, bytes]:
        """Finish receiving a file and start the function to process it.

        Parameters
        ----------
        task_and_file_names : str
            Task ID awaiting the file and the filename separated by a space (' ').

        Returns
        -------
        bytes
            Result.
        bytes
            Response message.
        """
        return super().end_receiving_file(task_and_file_names)

    async def setup_sync_wazuh_db_information(self, task_id: bytes, info_type: str):
        """Create a process to send to the local wazuh-db the chunks of data received from a worker.

        Parameters
        ----------
        task_id : bytes
            ID of the string where the JSON chunks are stored.
        info_type : str
            Information type handled.

        Returns
        -------
        result : bytes
            Worker's response after finishing the synchronization.
        """
        logger = ''
        command = ''
        error_command = ''
        timeout = 0
        sync_dict = {}
        if info_type == 'agent-info':
            logger = self.task_loggers['Agent-info sync']
            command = b'syn_m_a_e'
            error_command = b'syn_m_a_err'
            sync_dict = self.sync_agent_info_status
            timeout = self.cluster_items['intervals']['master']['timeout_agent_info']
        elif info_type == 'agent-groups':
            logger = self.task_loggers['Agent-groups sync']
            command = b'syn_m_g_e'
            error_command = b'syn_m_g_err'
            sync_dict = self.sync_agent_groups_status
            timeout = self.cluster_items['intervals']['master']['timeout_agent_groups']

        return await super().sync_wazuh_db_information(
            task_id=task_id, info_type=info_type, error_command=error_command,
            logger=logger, command=command, sync_dict=sync_dict, timeout=timeout)

    async def send_entire_agent_groups_information(self):
        """Method in charge of sending all the information related to
        agent-groups from the master node database to the worker node database.

        This method is activated when the worker node requests this information to the master node.
        """
        logger = self.task_loggers['Agent-groups full DB']
        sync_object = c_common.SyncWazuhdb(manager=self, logger=logger,
                                           data_retriever=WazuhDBConnection().run_wdb_command,
                                           get_data_command='global sync-agent-groups-get ',
                                           get_payload={"condition": "all", "set_synced": False,
                                                        "get_global_hash": True})
        local_agent_groups_information = await sync_object.retrieve_information()

        sync_object = c_common.SyncWazuhdb(manager=self, logger=logger, cmd=b'syn_g_m_w',
                                           data_retriever=WazuhDBConnection().run_wdb_command,
                                           set_data_command='global set-agent-groups',
                                           set_payload={'mode': 'override', 'sync_status': 'synced'})

        logger.info("Requested entire agent-groups information by the worker node. Starting.")
        start_time = perf_counter()
        await sync_object.sync(start_time=start_time, chunks=local_agent_groups_information)
        logger.info("Sent all agent-groups information from the master node database.")

        return b'ok', b'Sent'

    async def send_agent_groups_information(self):
        """Function in charge of sending the group information to the worker node.
        Each time we get data it will be sent.
        A worker node cannot send two consecutive times the same group information.
        """
        logger = self.task_loggers['Agent-groups send']
        wdb_conn = WazuhDBConnection()
        sync_object = c_common.SyncWazuhdb(manager=self, logger=logger, cmd=b'syn_g_m_w',
                                           data_retriever=wdb_conn.run_wdb_command,
                                           set_data_command='global set-agent-groups',
                                           set_payload={'mode': 'override', 'sync_status': 'synced'})

        while True:
            info = self.server.get_agent_groups_info(self.name)
            if info != {}:
                try:
                    self.send_agent_groups_status['date_start'] = perf_counter()
                    logger.info("Starting.")
                    await sync_object.sync(start_time=self.send_agent_groups_status['date_start'], chunks=info)
                except Exception as e:
                    logger.error(f'Error sending agent-groups information to {self.cluster_name}: {e}')

            await asyncio.sleep(1)

    async def sync_integrity(self, task_id: str, received_file: asyncio.Event):
        """Perform the integrity synchronization process by comparing local and received files.

        It waits until the worker sends its integrity metadata. Once received, they are unzipped.

        The information inside the unzipped files_metadata.json file (integrity metadata) is compared with the
        local one (updated every self.cluster_items['intervals']['master']['recalculate_integrity'] seconds).
        All files that are different (new, deleted, with a different MD5, etc) are classified into four groups:
        shared, missing, extra and extra_valid.

        Finally, a zip containing this classification (files_metadata.json) and the files that are missing
        or that must be updated are sent to the worker.

        Parameters
        ----------
        task_id : str
            ID of the asyncio task in charge of doing the sync process.
        received_file : asyncio.Event
            Asyncio event that is holding a lock while the files are not received.

        Returns
        -------
        bytes
            Result.
        bytes
            Response message.
        """
        logger = self.task_loggers['Integrity check']
        date_start_master = datetime.utcnow()
        logger.info("Starting.")

        logger.debug("Waiting to receive zip file from worker.")
        await asyncio.wait_for(received_file.wait(),
                               timeout=self.cluster_items['intervals']['communication']['timeout_receiving_file'])

        # Full path where the zip sent by the worker is located.
        received_filename = self.sync_tasks[task_id].filename
        if isinstance(received_filename, Exception):
            raise received_filename

        logger.debug(f"Received file from worker: '{received_filename}'")

        # Path to metadata file (files_metadata.json) and to zipdir (directory with decompressed files).
        files_metadata, decompressed_files_path = await wazuh.core.cluster.cluster.async_decompress_files(
            received_filename)
        # There are no files inside decompressed_files_path, only files_metadata.json which has already been loaded.
        shutil.rmtree(decompressed_files_path)

        # Classify files in shared, missing, extra and extra valid.
        worker_files_ko, counts = wazuh.core.cluster.cluster.compare_files(self.server.integrity_control,
                                                                           files_metadata, self.name)

        total_time = (datetime.utcnow() - date_start_master).total_seconds()
        self.extra_valid_requested = bool(worker_files_ko['extra_valid'])
        self.integrity_check_status.update({'date_start_master': date_start_master.strftime(decimals_date_format),
                                            'date_end_master': datetime.utcnow().strftime(decimals_date_format)})

        # Get the total number of files that require some change.
        if not functools.reduce(operator.add, map(len, worker_files_ko.values())):
            logger.info(f"Finished in {total_time:.3f}s. Received metadata of {len(files_metadata)} files. "
                        f"Sync not required.")
            result = await self.send_request(command=b'syn_m_c_ok', data=b'')
        else:
            logger.info(f"Finished in {total_time:.3f}s. Received metadata of {len(files_metadata)} files. "
                        f"Sync required.")

            logger = self.task_loggers['Integrity sync']
            logger.info("Starting.")
            self.integrity_sync_status.update({'tmp_date_start_master': datetime.utcnow(), 'total_files': counts,
                                               'total_extra_valid': 0})
            logger.info("Files to create in worker: {} | Files to update in worker: {} | Files to delete in worker: {} "
                        "| Files to receive: {}".format(len(worker_files_ko['missing']), len(worker_files_ko['shared']),
                                                        len(worker_files_ko['extra']),
                                                        len(worker_files_ko['extra_valid']))
                        )

            # Compress data: master files (only KO shared and missing).
            logger.debug("Compressing files to be synced in worker.")
            master_files_paths = worker_files_ko['shared'].keys() | worker_files_ko['missing'].keys()
            compressed_data = await cluster.run_in_pool(self.loop, self.server.task_pool,
                                                        wazuh.core.cluster.cluster.compress_files, self.name,
                                                        master_files_paths, worker_files_ko)

            try:
                # Start the synchronization process with the worker and get a taskID.
                task_id = await self.send_request(command=b'syn_m_c', data=b'')
                if isinstance(task_id, Exception) or task_id.startswith(b'Error'):
                    exc_info = task_id if isinstance(task_id, Exception) else \
                        exception.WazuhClusterError(3016, extra_message=str(task_id))
                    task_id = b'None'
                    raise exc_info

                # Send zip file to the worker into chunks.
                await self.send_file(compressed_data)
                logger.debug("Zip with files to be synced sent to worker.")

                # Finish the synchronization process and notify where the file corresponding to the taskID is located.
                result = await self.send_request(command=b'syn_m_c_e',
                                                 data=task_id + b' ' + os.path.relpath(
                                                     compressed_data, common.wazuh_path).encode())
                if isinstance(result, Exception):
                    raise result
                elif result.startswith(b'Error'):
                    raise exception.WazuhClusterError(3016, extra_message=result.decode())
            except exception.WazuhException as e:
                # Notify error to worker and delete its received file.
                self.logger.error(f"Error sending files information: {e}")
                result = await self.send_request(
                    command=b'syn_m_c_r', data=task_id + b' ' + json.dumps(e, cls=c_common.WazuhJSONEncoder).encode())
            except Exception as e:
                # Notify error to worker and delete its received file.
                self.logger.error(f"Error sending files information: {e}")
                exc_info = json.dumps(exception.WazuhClusterError(1000, extra_message=str(e)),
                                      cls=c_common.WazuhJSONEncoder).encode()
                result = await self.send_request(command=b'syn_m_c_r', data=task_id + b' ' + exc_info)
            finally:
                # Remove local file.
                os.unlink(compressed_data)
                logger.debug("Finished sending files to worker.")
                # Log 'Finished in' message only if there are no extra_valid files to sync.
                if not self.extra_valid_requested:
                    self.integrity_sync_status['date_end_master'] = datetime.utcnow()
                    logger.info("Finished in {:.3f}s.".format((self.integrity_sync_status['date_end_master'] -
                                                               self.integrity_sync_status['tmp_date_start_master'])
                                                              .total_seconds()))
                    self.integrity_sync_status['date_start_master'] = self.integrity_sync_status[
                        'tmp_date_start_master'].strftime(decimals_date_format)
                    self.integrity_sync_status['date_end_master'] = \
                        self.integrity_sync_status['date_end_master'].strftime(decimals_date_format)

        return result

    async def sync_extra_valid(self, task_id: str, received_file: asyncio.Event):
        """Run extra valid sync process and set up necessary parameters.

        Parameters
        ----------
        task_id : str
            ID of the asyncio task in charge of doing the sync process.
        received_file : asyncio.Event
            Asyncio event that is holding a lock while the files are not received.
        """
        logger = self.task_loggers['Integrity sync']
        await self.sync_worker_files(task_id, received_file, logger)
        self.integrity_sync_status['date_end_master'] = datetime.utcnow()
        logger.info("Finished in {:.3f}s.".format(
            (self.integrity_sync_status['date_end_master'] -
             self.integrity_sync_status['tmp_date_start_master']).total_seconds()))
        self.integrity_sync_status['date_start_master'] = \
            self.integrity_sync_status['tmp_date_start_master'].strftime(decimals_date_format)
        self.integrity_sync_status['date_end_master'] = \
            self.integrity_sync_status['date_end_master'].strftime(decimals_date_format)
        self.extra_valid_requested = False
        self.sync_integrity_free[0] = True

    async def sync_worker_files(self, task_id: str, received_file: asyncio.Event, logger):
        """Wait until extra valid files are received from the worker and create a child process for them.

        Parameters
        ----------
        task_id : str
            Task ID to which the file was sent.
        received_file : asyncio.Event
            Asyncio event that is holding a lock while the files are not received.
        logger : Logger object
            Logger to use (can't use self since one of the task loggers will be used).
        """
        logger.debug("Waiting to receive zip file from worker.")
        await asyncio.wait_for(received_file.wait(),
                               timeout=self.cluster_items['intervals']['communication']['timeout_receiving_file'])

        # Full path where the zip sent by the worker is located.
        received_filename = self.sync_tasks[task_id].filename
        if isinstance(received_filename, Exception):
            raise received_filename

        logger.debug(f"Received extra-valid file from worker: '{received_filename}'")

        # Path to metadata file (files_metadata.json) and to zipdir (directory with decompressed files).
        files_metadata, decompressed_files_path = await wazuh.core.cluster.cluster.async_decompress_files(
            received_filename)
        logger.debug(f"Received {len(files_metadata)} extra-valid files to check.")

        # Create a child process to run the task.
        try:
            result = await cluster.run_in_pool(self.loop, self.server.task_pool, self.process_files_from_worker,
                                               files_metadata, decompressed_files_path, self.cluster_items, self.name,
                                               self.cluster_items['intervals']['master']['timeout_extra_valid'])
        except Exception as e:
            raise exception.WazuhClusterError(3038, extra_message=str(e))
        finally:
            shutil.rmtree(decompressed_files_path)

        # Log any possible error found in the process.
        self.integrity_sync_status['total_extra_valid'] = result['total_updated']
        if result['errors_per_folder']:
            logger.error(f"Errors updating worker files: {dict(result['errors_per_folder'])}")
        for error in result['generic_errors']:
            logger.error(error)

    @staticmethod
    def process_files_from_worker(files_metadata: Dict, decompressed_files_path: str, cluster_items: dict,
                                  worker_name: str, timeout: int):
        """Iterate over received files from worker and updates the local ones.

        Parameters
        ----------
        files_metadata : dict
            Dictionary containing file metadata (each key is a filepath and each value its metadata).
        decompressed_files_path : str
            Filepath of the decompressed received zipfile.
        cluster_items : dict
            Object containing cluster internal variables from the cluster.json file.
        worker_name : str
            Name of the worker instance. Used to access the correct worker folder.
        timeout : int
            Seconds to wait before stopping the task.

        Returns
        -------
        result : dict
            Dict containing number of updated chunks and any error found in the process.
        """
        result = {'total_updated': 0, 'errors_per_folder': defaultdict(list), 'generic_errors': []}

        try:
            with utils.Timeout(timeout):
                for file_path, data in files_metadata.items():
                    full_path = os.path.join(common.wazuh_path, file_path)
                    item_key = data['cluster_item_key']

                    # Only valid client.keys is the local one (master).
                    if os.path.basename(file_path) == 'client.keys':
                        raise exception.WazuhClusterError(3007)

                    # If the file is merged, create individual files from it.
                    if data['merged']:
                        for unmerged_file_path, file_data, file_time in wazuh.core.cluster.cluster.unmerge_info(
                                data['merge_type'], decompressed_files_path, data['merge_name']
                        ):
                            try:
                                # Destination path.
                                full_unmerged_name = os.path.join(common.wazuh_path, unmerged_file_path)
                                # Path where to create the file before moving it to the destination path.
                                tmp_unmerged_path = os.path.join(common.wazuh_path, 'queue', 'cluster', worker_name,
                                                                 os.path.basename(unmerged_file_path))

                                # Format the file_data specified inside the merged file.
                                try:
                                    mtime = datetime.strptime(file_time, '%Y-%m-%d %H:%M:%S.%f')
                                except ValueError:
                                    mtime = datetime.strptime(file_time, '%Y-%m-%d %H:%M:%S')

                                # If the file already existed, check if it is older than the one from worker.
                                if os.path.isfile(full_unmerged_name):
                                    local_mtime = datetime.utcfromtimestamp(int(os.stat(full_unmerged_name).st_mtime))
                                    if local_mtime > mtime:
                                        continue

                                # Create file in temporal path and safe move it to the destination path.
                                with open(tmp_unmerged_path, 'wb') as f:
                                    f.write(file_data)

                                mtime_epoch = timegm(mtime.timetuple())
                                utils.safe_move(tmp_unmerged_path, full_unmerged_name,
                                                ownership=(common.wazuh_uid(), common.wazuh_gid()),
                                                permissions=cluster_items['files'][item_key]['permissions'],
                                                time=(mtime_epoch, mtime_epoch))
                                result['total_updated'] += 1
                            except TimeoutError as e:
                                raise e
                            except Exception as e:
                                result['errors_per_folder'][item_key].append(str(e))

                    # If the file is not 'merged' type, move it directly to the destination path.
                    else:
                        try:
                            zip_path = os.path.join(decompressed_files_path, file_path)
                            utils.safe_move(zip_path, full_path, ownership=(common.wazuh_uid(), common.wazuh_gid()),
                                            permissions=cluster_items['files'][item_key]['permissions'])
                        except TimeoutError as e:
                            raise e
                        except Exception as e:
                            result['errors_per_folder'][item_key].append(str(e))
        except TimeoutError:
            result['generic_errors'].append("Timeout processing extra-valid files.")
        except Exception as e:
            result['generic_errors'].append(f"Error updating worker files (extra valid): '{str(e)}'.")

        return result

    def get_logger(self, logger_tag: str = ''):
        """Get a logger object.

        Parameters
        ----------
        logger_tag : str
            Logger task to return. If empty, it will return main class logger.

        Returns
        -------
        Logger
            Logger object.
        """
        if logger_tag == '' or logger_tag not in self.task_loggers:
            return self.logger
        else:
            return self.task_loggers[logger_tag]

    def connection_lost(self, exc: Exception):
        """Close all pending tasks when connection with worker node is lost.

        Parameters
        ----------
        exc : Exception
            In case the connection was lost due to an exception, it will be available on this parameter.
        """
        super().connection_lost(exc)
        # cancel all pending tasks
        self.logger.info("Cancelling pending tasks.")
        for pending_task in self.sync_tasks.values():
            pending_task.task.cancel()


class Master(server.AbstractServer):
    """
    Create the server. Handle multiple clients, DAPI and Send Sync requests.
    """

    def __init__(self, **kwargs):
        """Class constructor.

        Parameters
        ----------
        kwargs
            Arguments for the parent class constructor.
        """
        super().__init__(**kwargs, tag="Master")
        self.agent_groups_control = {}
        self.agent_groups_control_workers = set()
        self.integrity_control = {}
        self.handler_class = MasterHandler
        try:
            self.task_pool = ProcessPoolExecutor(
                max_workers=min(os.cpu_count(), self.cluster_items['intervals']['master']['process_pool_size']))
        # Handle exception when the user running Wazuh cannot access /dev/shm
        except (FileNotFoundError, PermissionError):
            self.logger.warning(
                "In order to take advantage of Wazuh 4.3.0 cluster improvements, the directory '/dev/shm' must be "
                "accessible by the 'wazuh' user. Check that this file has permissions to be accessed by all users. "
                "Changing the file permissions to 777 will solve this issue.")
            self.logger.warning(
                "The Wazuh cluster will be run without the improvements added in Wazuh 4.3.0 and higher versions.")
            self.task_pool = None
        self.integrity_already_executed = []
        self.dapi = dapi.APIRequestQueue(server=self)
        self.sendsync = dapi.SendSyncRequestQueue(server=self)
        self.tasks.extend([self.dapi.run, self.sendsync.run, self.file_status_update, self.agent_groups_update])
        # pending API requests waiting for a response
        self.pending_api_requests = {}

    def to_dict(self) -> Dict:
        """Get master's healthcheck information.

        Returns
        -------
        dict
            Healthcheck and basic information from master node.
        """
        return {'info': {'name': self.configuration['node_name'], 'type': self.configuration['node_type'],
                         'version': metadata.__version__, 'ip': self.configuration['nodes'][0]}}

    def get_agent_groups_info(self, client):
        """Check whether the updated group information is sent only once per worker.

        The variable with this information will not be updated until all the MasterHandlers send
        the information to their worker node.

        Parameters
        ----------
        client : str
            String with the node name.

        Returns
        -------
        result : dict
            Updated data on agent-groups.
        """
        result = {}
        if client not in self.agent_groups_control_workers:
            result = self.agent_groups_control
            self.agent_groups_control_workers.add(client)

        return result

    async def agent_groups_update(self):
        """Asynchronous task in charge of obtaining data related to agent-groups periodically.

        It updates the local variable agent_groups_control
        every self.cluster_items['intervals']['master']['sync_agent_groups'] seconds.

        This information will only be sent to the worker nodes when it contains data.
        It looks like this: ['[{"data":[{"id":1,"group":["default","group1"]}]}]'].
        """
        logger = self.setup_task_logger('Agent-groups get')
        wdb_conn = WazuhDBConnection()
        sync_object = c_common.SyncWazuhdb(manager=self, logger=logger, cmd=b'syn_g_m_w',
                                           data_retriever=wdb_conn.run_wdb_command,
                                           get_data_command='global sync-agent-groups-get ',
                                           get_payload={"condition": "sync_status", "set_synced": True,
                                                        "get_global_hash": True})

        while True:
            try:
                before = perf_counter()
                sync_object.logger.info("Starting.")
                if len(self.agent_groups_control_workers) >= len(self.clients.keys()) > 0:
                    self.agent_groups_control = await sync_object.retrieve_information()
                    self.agent_groups_control_workers.clear()
                    after = perf_counter()
                    logger.info(f"Finished in {(after - before):.3f}s.")
                elif len(self.clients.keys()) == 0:
                    logger.info("No clients connected. Skipping.")
            except Exception as e:
                sync_object.logger.error(f"Error getting agent-groups from WDB: {e}")

            await asyncio.sleep(self.cluster_items['intervals']['master']['sync_agent_groups'])

    async def file_status_update(self):
        """Asynchronous task that obtain files status periodically.
        It updates the local files information every self.cluster_items['intervals']['worker']['sync_integrity']
        seconds.

        A dictionary like {'file_path': {<MD5, merged, merged_name, etc>}, ...} is created and later
        compared with the one received from the workers to find out which files are different, missing or removed.
        """
        file_integrity_logger = self.setup_task_logger("Local integrity")
        while True:
            before = datetime.utcnow()
            file_integrity_logger.info("Starting.")
            try:
                self.integrity_control = await cluster.run_in_pool(self.loop, self.task_pool,
                                                                   wazuh.core.cluster.cluster.get_files_status,
                                                                   self.integrity_control)
            except Exception as e:
                file_integrity_logger.error(f"Error calculating local file integrity: {e}")
            finally:
                # With this we avoid that each worker starts integrity_check more than once per local_integrity
                self.integrity_already_executed.clear()

            file_integrity_logger.info(f"Finished in {(datetime.utcnow() - before).total_seconds():.3f}s. Calculated "
                                       f"metadata of {len(self.integrity_control)} files.")

            await asyncio.sleep(self.cluster_items['intervals']['master']['recalculate_integrity'])

    def get_health(self, filter_node) -> Dict:
        """Get nodes and synchronization information.

        Parameters
        ----------
        filter_node : dict
            Whether to filter by a node or return all health information.

        Returns
        -------
        dict
            Dict object containing nodes information.
        """
        workers_info = {key: val.to_dict() for key, val in self.clients.items()
                        if filter_node is None or filter_node == {} or key in filter_node}
        n_connected_nodes = len(workers_info)
        if filter_node is None or self.configuration['node_name'] in filter_node:
            workers_info.update({self.configuration['node_name']: self.to_dict()})

        # Get active agents by node and format last keep alive date format
        active_agents = Agent.get_agents_overview(filters={'status': 'active', 'node_name': filter_node})['items']
        for agent in active_agents:
            if (agent_node := agent["node_name"]) in workers_info.keys():
                workers_info[agent_node]["info"]["n_active_agents"] = \
                    workers_info[agent_node]["info"].get("n_active_agents", 0) + 1
        for node_name in workers_info.keys():
            if workers_info[node_name]["info"].get("n_active_agents") is None:
                workers_info[node_name]["info"]["n_active_agents"] = 0
            if workers_info[node_name]['info']['type'] != 'master':
                workers_info[node_name]['status']['last_keep_alive'] = str(
                    datetime.utcfromtimestamp(workers_info[node_name]['status']['last_keep_alive']
                                              ).strftime(decimals_date_format))

        return {"n_connected_nodes": n_connected_nodes, "nodes": workers_info}

    def get_node(self) -> Dict:
        """Get basic information about the node.

        Returns
        -------
        dict
            Basic node information.
        """
        return {'type': self.configuration['node_type'], 'cluster': self.configuration['name'],
                'node': self.configuration['node_name']}
