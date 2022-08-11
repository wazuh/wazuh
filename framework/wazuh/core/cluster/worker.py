# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import asyncio
import errno
import json
import os
import shutil
import time
from typing import Tuple, Dict, Callable, List
from typing import Union

from wazuh.core import cluster as metadata, common, exception, utils
from wazuh.core.cluster import local_client, client, cluster, common as c_common
from wazuh.core.cluster.dapi import dapi
from wazuh.core.exception import WazuhClusterError
from wazuh.core.utils import safe_move
from wazuh.core.wdb import WazuhDBConnection


class ReceiveIntegrityTask(c_common.ReceiveFileTask):
    """
    Create an asyncio.Task that waits until the master sends its integrity information and processes the
    received information.
    """

    def set_up_coro(self) -> Callable:
        """Set up the function to process the integrity files received from master."""
        return self.wazuh_common.process_files_from_master

    def done_callback(self, future=None):
        """Free the integrity sync lock and remove the task_id.

        Parameters
        ----------
        future : asyncio.Future object
            Synchronization process result.
        """
        self.wazuh_common.check_integrity_free = True
        super().done_callback(future)


class SyncTask:
    """
    Common class for all worker sync tasks.
    """

    def __init__(self, cmd: bytes, logger, worker):
        """Class constructor.

        Parameters
        ----------
        cmd : bytes
            Request command to send to the master.
        logger : Logger object
            Logger to use during synchronization process.
        worker : WorkerHandler object
            The WorkerHandler object that creates this one.
        """
        self.cmd = cmd
        self.logger = logger
        self.worker = worker

    async def request_permission(self):
        """Request permission to start synchronization process with the master.

        Returns
        -------
        bool
            Whether permission is granted.
        """
        result = await self.worker.send_request(command=self.cmd+b'_p', data=b'')

        if isinstance(result, Exception):
            self.logger.error(f"Error asking for permission: {result}")
        elif result == b'True':
            self.logger.debug("Permission to synchronize granted.")
            return True
        else:
            self.logger.debug(f"Master didn't grant permission to start a new synchronization: {result}")

        return False

    async def sync(self, *args, **kwargs):
        """Define sync() method. It is implemented differently for files and strings synchronization.

        Parameters
        ----------
        args
            Positional arguments for parent constructor class.
        kwargs
            Keyword arguments for parent constructor class.

        Raises
        -------
        NotImplementedError
            If the method is not implemented.
        """
        raise NotImplementedError


class SyncFiles(SyncTask):
    """
    Define methods to synchronize files with master.
    """

    async def sync(self, files_to_sync: Dict, files_metadata: Dict):
        """Send metadata and files to the master node.

        Parameters
        ----------
        files_to_sync : dict
            Paths (keys) and metadata (values) of the files to send to the master. Keys in this dictionary
            will be iterated to add the files they refer to the zip file that the master will receive.
        files_metadata : dict
            Paths (keys) and metadata (values) of the files to send to the master. This dict will be included as
            a JSON file named files_metadata.json.

        Returns
        -------
        bool
            True if files were correctly sent to the master node, None otherwise.
        """
        # Start the synchronization process with the master and get a taskID.
        task_id = await self.worker.send_request(command=self.cmd, data=b'')
        if isinstance(task_id, Exception):
            raise task_id
        elif task_id.startswith(b'Error'):
            self.logger.error(task_id.decode())
            exc_info = json.dumps(exception.WazuhClusterError(3016, extra_message=str(task_id)),
                                  cls=c_common.WazuhJSONEncoder).encode()
            await self.worker.send_request(command=self.cmd + b'_r', data=b'None ' + exc_info)
            return

        self.logger.debug(
            f"Compressing {'files and ' if files_to_sync else ''}'files_metadata.json' of {len(files_metadata)} files."
        )
        compressed_data_path = cluster.compress_files(name=self.worker.name, list_path=files_to_sync,
                                                      cluster_control_json=files_metadata)

        try:
            # Send zip file to the master into chunks.
            self.logger.debug("Sending zip file to master.")
            await self.worker.send_file(filename=compressed_data_path)
            self.logger.debug("Zip file sent to master.")

            # Finish the synchronization process and notify where the file corresponding to the taskID is located.
            result = await self.worker.send_request(command=self.cmd + b'_e', data=task_id + b' ' +
                                                    os.path.relpath(compressed_data_path, common.wazuh_path).encode())
            if isinstance(result, Exception):
                raise result
            elif result.startswith(b'Error'):
                raise WazuhClusterError(3016, extra_message=result.decode())
            return True
        except exception.WazuhException as e:
            # Notify error to master and delete its received file.
            self.logger.error(f"Error sending zip file: {e}")
            await self.worker.send_request(command=self.cmd+b'_r', data=task_id + b' ' +
                                           json.dumps(e, cls=c_common.WazuhJSONEncoder).encode())
        except Exception as e:
            # Notify error to master and delete its received file.
            self.logger.error(f"Error sending zip file: {e}")
            exc_info = json.dumps(exception.WazuhClusterError(1000, extra_message=str(e)),
                                  cls=c_common.WazuhJSONEncoder).encode()
            await self.worker.send_request(command=self.cmd+b'_r', data=task_id + b' ' + exc_info)
        finally:
            os.unlink(compressed_data_path)


class SyncWazuhdb(SyncTask):
    """
    Define methods to send information to the master node (wazuh-db) through send_string protocol.
    """

    def __init__(self, worker, logger, cmd: bytes, get_data_command: str, set_data_command: str,
                 data_retriever: Callable):
        """Class constructor.

        Parameters
        ----------
        worker : WorkerHandler object
            The WorkerHandler object that creates this one.
        cmd : bytes
            Request command to send to the master.
        get_data_command : str
            Command to retrieve data from local wazuh-db.
        set_data_command : str
            Command to set data in master's wazuh-db.
        logger : Logger object
            Logger to use during synchronization process.
        data_retriever : Callable
            Function to be called to obtain chunks of data. It must return a list of chunks.
        """
        super().__init__(worker=worker, logger=logger, cmd=cmd)
        self.get_data_command = get_data_command
        self.set_data_command = set_data_command
        self.data_retriever = data_retriever

    async def sync(self, start_time: float):
        """Start sending information to master node.

        Parameters
        ----------
        start_time : float
            Start time to be used when logging task duration if master's response is not expected.

        Returns
        -------
        bool
            True if data was correctly sent to the master node, None otherwise.
        """
        try:
            # Retrieve information from local wazuh-db
            get_chunks_start_time = time.time()
            chunks = self.data_retriever(self.get_data_command)
            self.logger.debug(f"Obtained {len(chunks)} chunks of data in {(time.time() - get_chunks_start_time):.3f}s.")
        except exception.WazuhException as e:
            self.logger.error(f"Error obtaining data from wazuh-db: {e}")
            return

        if chunks:
            # Send list of chunks as a JSON string
            data = json.dumps({"set_data_command": self.set_data_command, "chunks": chunks}).encode()
            task_id = await self.worker.send_string(data)
            if task_id.startswith(b'Error'):
                raise WazuhClusterError(3016, extra_message=f'agent-info string could not be sent to the master '
                                                            f'node: {task_id}')

            # Specify under which task_id the JSON can be found in the master.
            await self.worker.send_request(command=self.cmd, data=task_id)
            self.logger.debug(f"All chunks sent.")
        else:
            self.logger.info(f"Finished in {(time.time() - start_time):.3f}s (0 chunks sent).")
        return True


class RetrieveAndSendToMaster:
    """
    Define methods to send information to self.daemon in the master through sendsync protocol.
    """

    def __init__(self, worker, destination_daemon, data_retriever: callable, logger=None, msg_format='{payload}',
                 n_retries=3, retry_time=0.2, max_retry_time_allowed=10, cmd=None, expected_res='ok'):
        """Class constructor.

        Parameters
        ----------
        worker : WorkerHandler object
            Instance of worker object.
        destination_daemon : str
            Daemon name on the master node to which send information.
        cmd : bytes
            Command to inform the master when the synchronization process starts and ends.
        data_retriever : Callable
            Function to be called to obtain chunks of data. It must return a list of chunks.
        logger : Logger object, optional
             Logger to use during synchronization process.
        msg_format : str, optional
            Format of the message to be executed in the master's daemon. It must
            contain the label '{payload}', which will be replaced with every chunk of data.
            I. e: 'global sync-agent-info-set {payload}'
        n_retries : int, optional
            Number of times a chunk has to be resent when it fails.
        retry_time : float, optional
            Time between resend attempts. It is multiplied by the number of retries carried out.
        max_retry_time_allowed : float, optional
            Maximum total time allowed to retry failed requests. If this time has already been
            elapsed, no new attempts will be made to resend all the chunks which response
            does not begin with {expected_res}.
        expected_res : str, optional
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
        """Start synchronization process with the master and send necessary information.

        This method retrieves a list of payloads/chunks from self.data_retriever(*args, **kwargs).
        The chunks are sent one by one through sendsync command.

        Parameters
        ----------
        args, optional
            Variable length argument list to be sent as parameter to data_retriever callable.
        kwargs, optional
            Arbitrary keyword arguments to be sent as parameter to data_retriever callable.

        Returns
        -------
        chunks_sent : int
            Number of successfully sent chunks.
        """
        before = time.time()
        self.logger.debug(f"Obtaining data to be sent to master's {self.daemon}.")
        try:
            chunks_to_send = self.data_retriever(*args, **kwargs)
            self.logger.debug(f"Obtained {len(chunks_to_send)} chunks of data to be sent.")
        except exception.WazuhException as e:
            self.logger.error(f"Error obtaining data: {e}")
            return

        if self.cmd:
            # Send command to master so it knows when the task starts.
            result = await self.worker.send_request(command=self.cmd + b'_s', data=b'')
            self.logger.debug(f"Master response for {self.cmd+b'_s'} command: {result}")

        chunks_sent = 0
        start_time = time.time()

        self.logger.debug(f"Starting to send information to {self.daemon}.")
        for chunk in chunks_to_send:
            data = json.dumps({
                'daemon_name': self.daemon,
                'message': self.msg_format.format(payload=chunk)
            }).encode()

            try:
                # Send chunk of data to self.daemon of the master.
                result = await self.lc.execute(command=b'sendasync', data=data, wait_for_complete=False)
                self.logger.debug(f"Master's {self.daemon} response: {result}.")

                # Retry self.n_retries if result was not ok.
                if not result.startswith(self.expected_res):
                    for i in range(self.n_retries):
                        if (time.time() - start_time) < self.max_retry_time_allowed:
                            await asyncio.sleep(i * self.retry_time)
                            self.logger.error(f"Error sending chunk to master's {self.daemon}. Response does not start "
                                              f"with {self.expected_res} (Response: {result}). Retrying... {i}.")
                            result = await self.lc.execute(command=b'sendasync', data=data, wait_for_complete=False)
                            self.logger.debug(f"Master's {self.daemon} response: {result}.")
                            if result.startswith(self.expected_res):
                                chunks_sent += 1
                                break
                        else:
                            self.logger.error(f"Error sending chunk to master's {self.daemon}. Response does not start "
                                              f"with {self.expected_res}. Not retrying because total time exceeded "
                                              f"{self.max_retry_time_allowed} seconds.")
                            break
                else:
                    chunks_sent += 1

            except exception.WazuhException as e:
                self.logger.error(f"Error sending information to {self.daemon}: {e}")

        if self.cmd:
            # Send command to master so it knows when the task ends.
            result = await self.worker.send_request(command=self.cmd + b'_e', data=str(chunks_sent).encode())
            self.logger.debug(f"Master response for {self.cmd+b'_e'} command: {result}")

        self.logger.debug(f"Finished sending information to {self.daemon} in {(time.time() - before):.3f}s.")

        return chunks_sent


class WorkerHandler(client.AbstractClient, c_common.WazuhCommon):
    """
    Handle connection with the master node.
    """

    def __init__(self, version, node_type, cluster_name, **kwargs):
        """Class constructor.

        Parameters
        ----------
        version : str
            Wazuh version. E.g., '4.0.0'.
        node_type : str
            Type of node (will always be worker but it's set as a variable in case more types are added in the future).
        cluster_name : str
            The cluster name.
        **kwargs
            Arguments for the parent class constructor.
        """
        super().__init__(**kwargs, tag="Worker")
        # The self.client_data will be sent to the master when doing a hello request.
        self.client_data = f"{self.name} {cluster_name} {node_type} {version}".encode()

        # Flag to prevent a new Integrity check if Integrity sync is in progress.
        self.check_integrity_free = True

        # Every task logger is configured to log using a tag describing the synchronization process. For example,
        # a log coming from the "Integrity" logger will look like this:
        # [Worker name] [Integrity] Log information
        # this way the same code can be shared among all sync tasks and logs will differentiate.
        self.task_loggers = {'Agent-info sync': self.setup_task_logger('Agent-info sync'),
                             'Integrity check': self.setup_task_logger('Integrity check'),
                             'Integrity sync': self.setup_task_logger('Integrity sync')}

        self.agent_info_sync_status = {'date_start': 0.0}
        self.integrity_check_status = {'date_start': 0.0}
        self.integrity_sync_status = {'date_start': 0.0}

    def connection_result(self, future_result):
        """Callback function called when the master sends a response to the hello command sent by the worker.

        Parameters
        ----------
        future_result : asyncio.Future object
            Result of the hello request.
        """
        super().connection_result(future_result)
        if self.connected:
            # create directory for temporary files
            worker_tmp_files = os.path.join(common.wazuh_path, 'queue', 'cluster', self.name)
            if not os.path.exists(worker_tmp_files):
                utils.mkdir_with_mode(worker_tmp_files)

    def process_request(self, command: bytes, data: bytes) -> Union[bytes, Tuple[bytes, bytes]]:
        """Define all commands that a worker can receive from the master.

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
        self.logger.debug(f"Command received: '{command}'")
        if command == b'syn_m_c_ok':
            return self.sync_integrity_ok_from_master()
        elif command == b'syn_m_c':
            return self.setup_receive_files_from_master()
        elif command == b'syn_m_c_e':
            return self.end_receiving_integrity(data.decode())
        elif command == b'syn_m_c_r':
            return self.error_receiving_integrity(data.decode())
        elif command == b'syn_m_a_e':
            return self.sync_agent_info_from_master(data.decode())
        elif command == b'syn_m_a_err':
            return self.error_receiving_agent_info(data.decode())
        elif command == b'dapi_res':
            asyncio.create_task(self.forward_dapi_response(data))
            return b'ok', b'Response forwarded to worker'
        elif command == b'sendsyn_res':
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
        elif command == b'sendsyn_err':
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
        """Get the Worker object that created this WorkerHandler. Used in the class WazuhCommon.

        Returns
        -------
        AbstractClientManager
            Worker object.
        """
        return self.manager

    def setup_receive_files_from_master(self):
        """Set up a task to wait until integrity information has been received from the master and process it.

        Returns
        -------
        bytes
            Result.
        bytes
            Response message.
        """
        integrity_logger = self.task_loggers['Integrity check']
        integrity_logger.info(f"Finished in {(time.time() - self.integrity_check_status['date_start']):.3f}s. "
                              f"Sync required.")
        self.check_integrity_free = False
        return super().setup_receive_file(ReceiveIntegrityTask)

    def end_receiving_integrity(self, task_and_file_names: str) -> Tuple[bytes, bytes]:
        """Notify to the corresponding task that information has been received.

        The master notifies to this the worker that the integrity information has already been sent.
        Then, the worker notifies the previously created task that the information has been received.

        Parameters
        ----------
        task_and_file_names : str
            Task ID and a filename, separated by a space (' ').

        Returns
        -------
        bytes
            Result.
        bytes
            Response message.
        """
        return super().end_receiving_file(task_and_file_names)

    def error_receiving_integrity(self, taskname_and_error_details: str) -> Tuple[bytes, bytes]:
        """Notify to the corresponding task that an error has occurred during the process.

        Parameters
        ----------
        taskname_and_error_details : str
            Task ID and error formatted as WazuhJSONEncoder.

        Returns
        -------
        bytes
            Result.
        bytes
            Response message.
        """
        return super().error_receiving_file(taskname_and_error_details)

    def sync_integrity_ok_from_master(self) -> Tuple[bytes, bytes]:
        """Function called when the master sends the "syn_m_c_ok" command.

        Returns
        -------
        bytes
            Result.
        bytes
            Response message.
        """
        integrity_logger = self.task_loggers['Integrity check']
        integrity_logger.info(f"Finished in {(time.time() - self.integrity_check_status['date_start']):.3f}s. "
                              f"Sync not required.")
        return b'ok', b'Thanks'

    def sync_agent_info_from_master(self, response) -> Tuple[bytes, bytes]:
        """Function called when the master sends the "syn_m_a_e" command.

        This method is called once the master finishes processing the agent-info. It logs
        information like the number of chunks that were updated and any error message.

        Parameters
        ----------
        response : str
            JSON containing information about agent-info sync status.

        Returns
        -------
        bytes
            Result.
        bytes
            Response message.
        """
        logger = self.task_loggers['Agent-info sync']
        data = json.loads(response)
        msg = f"Finished in {(time.time()-self.agent_info_sync_status['date_start']):.3f}s ({data['updated_chunks']} " \
              f"chunks updated)."
        logger.info(msg) if not data['error_messages'] else logger.error(
            msg + f" There were {len(data['error_messages'])} chunks with errors: {data['error_messages']}")

        return b'ok', b'Thanks'

    def error_receiving_agent_info(self, response):
        """Function called when the master sends the "syn_m_a_err" command.

        Parameters
        ----------
        response : str
            Message with extra information of the error.

        Returns
        -------
        bytes
            Result.
        bytes
            Response message.
        """
        logger = self.task_loggers['Agent-info sync']
        logger.error(f"There was an error while processing agent-info on the master: {response}")

        return b'ok', b'Thanks'

    async def sync_integrity(self):
        """Obtain files status and send it to the master.

        Asynchronous task that is started when the worker connects to the master. It starts an integrity synchronization
        process every self.cluster_items['intervals']['worker']['sync_integrity'] seconds.

        A dictionary like {'file_path': {<MD5, merged, merged_name, etc>}, ...} is created and sent to the master,
        containing the information of all the files inside the directories specified in cluster.json. The master
        compares it with its own information.
        """
        logger = self.task_loggers["Integrity check"]
        integrity_check = SyncFiles(cmd=b'syn_i_w_m', logger=logger, worker=self)

        while True:
            try:
                if self.connected:
                    start_time = time.time()
                    if self.check_integrity_free and await integrity_check.request_permission():
                        logger.info("Starting.")
                        self.integrity_check_status['date_start'] = start_time
                        self.manager.integrity_control = await cluster.run_in_pool(self.loop, self.manager.task_pool,
                                                                                   cluster.get_files_status,
                                                                                   self.manager.integrity_control)
                        await integrity_check.sync(files_metadata=self.manager.integrity_control, files_to_sync={})
            # If exception is raised during sync process, notify the master so it removes the file if received.
            except exception.WazuhException as e:
                logger.error(f"Error synchronizing integrity: {e}")
                await self.send_request(command=b'syn_i_w_m_r', data=b'None ' +
                                        json.dumps(e, cls=c_common.WazuhJSONEncoder).encode())
            except Exception as e:
                logger.error(f"Error synchronizing integrity: {e}")
                exc_info = json.dumps(exception.WazuhClusterError(1000, extra_message=str(e)),
                                      cls=c_common.WazuhJSONEncoder)
                await self.send_request(command=b'syn_i_w_m_r', data=b'None ' + exc_info.encode())

            await asyncio.sleep(self.cluster_items['intervals']['worker']['sync_integrity'])

    async def sync_agent_info(self):
        """Obtain information from agents reporting this worker and send it to the master.

        Asynchronous task that is started when the worker connects to the master. It starts an agent-info
        synchronization process every 'sync_agent_info' seconds.

        A list of JSON chunks with the information of all local agents is retrieved from local wazuh-db socket
        and sent to the master's wazuh-db.
        """
        logger = self.task_loggers["Agent-info sync"]
        wdb_conn = WazuhDBConnection()
        synced = True
        agent_info = SyncWazuhdb(worker=self, logger=logger, cmd=b'syn_a_w_m', data_retriever=wdb_conn.run_wdb_command,
                                 get_data_command='global sync-agent-info-get ',
                                 set_data_command='global sync-agent-info-set')

        while True:
            try:
                if self.connected:
                    start_time = time.time()
                    if await agent_info.request_permission():
                        logger.info("Starting.")
                        self.agent_info_sync_status['date_start'] = start_time
                        await agent_info.sync(start_time=start_time)
            except Exception as e:
                logger.error(f"Error synchronizing agent info: {e}")

            await asyncio.sleep(
                self.cluster_items['intervals']['worker']['sync_agent_info' if synced else 'sync_agent_info_ko_retry'])

    async def sync_extra_valid(self, extra_valid: Dict):
        """Merge and send files of the worker node that are missing in the master node.

        Asynchronous task that is started when the master requests any extra valid files to be synchronized.
        That means, it is started in the sync_integrity process.

        Parameters
        ----------
        extra_valid : dict
            Keys are paths of files missing in the master node.
        """
        logger = self.task_loggers["Integrity sync"]

        try:
            before = time.time()
            logger.debug("Starting sending extra valid files to master.")
            extra_valid_sync = SyncFiles(cmd=b'syn_e_w_m', logger=logger, worker=self)

            # Merge all agent-groups files into one and create metadata dict with it (key->filepath, value->metadata).
            n_files, merged_file = cluster.merge_info(merge_type='agent-groups', node_name=self.name,
                                                      files=extra_valid.keys())
            files_to_sync = {merged_file: {'merged': True, 'merge_type': 'agent-groups', 'merge_name': merged_file,
                                           'cluster_item_key': 'queue/agent-groups/'}} if n_files else {}

            # Permission is not requested since it was already granted in the 'Integrity check' task.
            await extra_valid_sync.sync(files_to_sync=files_to_sync, files_metadata=files_to_sync)
            after = time.time()
            logger.debug(f"Finished sending extra valid files in {(after - before):.3f}s.")
            logger.info(f"Finished in {(after - self.integrity_sync_status['date_start']):.3f}s.")

        # If exception is raised during sync process, notify the master so it removes the file if received.
        except exception.WazuhException as e:
            logger.error(f"Error synchronizing extra valid files: {e}")
            await self.send_request(command=b'syn_i_w_m_r',
                                    data=b'None ' + json.dumps(e, cls=c_common.WazuhJSONEncoder).encode())
        except Exception as e:
            logger.error(f"Error synchronizing extra valid files: {e}")
            exc_info = json.dumps(exception.WazuhClusterError(1000, extra_message=str(e)),
                                  cls=c_common.WazuhJSONEncoder)
            await self.send_request(command=b'syn_i_w_m_r', data=b'None ' + exc_info.encode())

    async def process_files_from_master(self, name: str, file_received: asyncio.Event):
        """Perform relevant actions for each file according to its status.

        Process integrity files coming from the master. It updates necessary information and sends the master
        any required extra_valid files.

        Parameters
        ----------
        name : str
            Task ID that was waiting for the file to be received.
        file_received : asyncio.Event
            Asyncio event that is unlocked once the file has been received.
        """
        logger = self.task_loggers['Integrity sync']

        try:
            await asyncio.wait_for(file_received.wait(),
                                   timeout=self.cluster_items['intervals']['communication']['timeout_receiving_file'])
        except Exception:
            await self.send_request(
                command=b'syn_i_w_m_r',
                data=b'None ' + json.dumps(timeout_exc := WazuhClusterError(
                    3039, extra_message=f'Integrity sync at {self.name}'), cls=c_common.WazuhJSONEncoder).encode())
            raise timeout_exc

        if isinstance(self.sync_tasks[name].filename, Exception):
            exc_info = json.dumps(exception.WazuhClusterError(
                1000, extra_message=str(self.sync_tasks[name].filename)), cls=c_common.WazuhJSONEncoder)
            await self.send_request(command=b'syn_i_w_m_r', data=b'None ' + exc_info.encode())
            raise self.sync_tasks[name].filename

        zip_path = ""
        # Path of the zip containing a JSON with metadata and files to be updated in this worker node.
        received_filename = self.sync_tasks[name].filename

        try:
            self.integrity_sync_status['date_start'] = time.time()
            logger.info("Starting.")

            """
            - zip_path contains the path of the unzipped directory
            - ko_files contains a Dict with this structure:
              {'missing': {'<file_path>': {<MD5, merged, merged_name, etc>}, ...},
               'shared': {...}, 'extra': {...}, 'extra_valid': {...}}
            """
            ko_files, zip_path = await cluster.run_in_pool(self.loop, self.manager.task_pool, cluster.decompress_files,
                                                           received_filename)
            logger.info("Files to create: {} | Files to update: {} | Files to delete: {} | Files to send: {}".format(
                len(ko_files['missing']), len(ko_files['shared']), len(ko_files['extra']), len(ko_files['extra_valid']))
            )

            if ko_files['shared'] or ko_files['missing'] or ko_files['extra']:
                # Update or remove files in this worker node according to their status (missing, extra or shared).
                logger.debug("Worker does not meet integrity checks. Actions required.")
                logger.debug("Updating local files: Start.")
                await cluster.run_in_pool(self.loop, self.manager.task_pool, self.update_master_files_in_worker,
                                          ko_files, zip_path, self.cluster_items, self.task_loggers['Integrity sync'])
                logger.debug("Updating local files: End.")

            # Send extra valid files to the master.
            if ko_files['extra_valid']:
                logger.debug("Master requires some worker files.")
                asyncio.create_task(self.sync_extra_valid(ko_files['extra_valid']))
            else:
                logger.info(f"Finished in {time.time() - self.integrity_sync_status['date_start']:.3f}s.")

        except exception.WazuhException as e:
            logger.error(f"Error synchronizing extra valid files: {e}")
            await self.send_request(command=b'syn_i_w_m_r',
                                    data=b'None ' + json.dumps(e, cls=c_common.WazuhJSONEncoder).encode())
        except Exception as e:
            logger.error(f"Error synchronizing extra valid files: {e}")
            exc_info = json.dumps(exception.WazuhClusterError(1000, extra_message=str(e)),
                                  cls=c_common.WazuhJSONEncoder)
            await self.send_request(command=b'syn_i_w_m_r', data=b'None ' + exc_info.encode())
        finally:
            zip_path and shutil.rmtree(zip_path)

    @staticmethod
    def update_master_files_in_worker(ko_files: Dict, zip_path: str, cluster_items: Dict, logger):
        """Iterate over received files and updates them locally.

        Parameters
        ----------
        ko_files : dict
            File metadata coming from the master.
        zip_path : str
            Pathname of the unzipped directory received from master and containing the files to update.
        cluster_items : dict
            Object containing cluster internal variables from the cluster.json file.
        logger : Logger object
            Logger to use.
        """

        def overwrite_or_create_files(filename: str, data: Dict):
            """Update a file coming from the master.

            Move a file which is inside the unzipped directory that comes from master to the path
            specified in 'filename'. If the file is 'merged' type, it is first split into files
            and then moved to their final directory.

            Parameters
            ----------
            filename : str
                Filename inside unzipped dir to update.
            data : dict
                File metadata such as modification time, whether it's a merged file or not, etc.
            """
            full_filename_path = os.path.join(common.wazuh_path, filename)

            if data['merged']:  # worker nodes can only receive agent-groups files
                # Split merged file into individual files inside zipdir (directory containing unzipped files),
                # and then move each one to the destination directory (<wazuh_path>/filename).
                for name, content, _ in cluster.unmerge_info('agent-groups', zip_path, filename):
                    full_unmerged_name = os.path.join(common.wazuh_path, name)
                    tmp_unmerged_path = full_unmerged_name + '.tmp'
                    with open(tmp_unmerged_path, 'wb') as f:
                        f.write(content)
                    safe_move(tmp_unmerged_path, full_unmerged_name,
                              permissions=cluster_items['files'][data['cluster_item_key']]['permissions'],
                              ownership=(common.wazuh_uid(), common.wazuh_gid())
                              )
            else:
                # Create destination dir if it doesn't exist.
                if not os.path.exists(os.path.dirname(full_filename_path)):
                    utils.mkdir_with_mode(os.path.dirname(full_filename_path))
                # Move the file from zipdir (directory containing unzipped files) to <wazuh_path>/filename.
                safe_move(os.path.join(zip_path, filename), full_filename_path,
                          permissions=cluster_items['files'][data['cluster_item_key']]['permissions'],
                          ownership=(common.wazuh_uid(), common.wazuh_gid())
                          )

        errors = {'shared': 0, 'missing': 0, 'extra': 0}

        for filetype, files in ko_files.items():
            # Overwrite local files marked as shared or missing.
            if filetype == 'shared' or filetype == 'missing':
                logger.debug(f"Received {len(ko_files[filetype])} {filetype} files to update from master.")
                for filename, data in files.items():
                    try:
                        logger.debug2(f"Processing file {filename}")
                        overwrite_or_create_files(filename, data)
                    except Exception as e:
                        errors[filetype] += 1
                        logger.error(f"Error processing {filetype} file '{filename}': {e}")
                        continue
            # Remove local files marked as extra.
            elif filetype == 'extra':
                for file_to_remove in files:
                    try:
                        logger.debug2(f"Remove file: '{file_to_remove}'")
                        file_path = os.path.join(common.wazuh_path, file_to_remove)
                        try:
                            os.remove(file_path)
                        except OSError as e:
                            if e.errno == errno.ENOENT and 'queue/agent-groups/' in file_path:
                                logger.debug2(f"File {file_to_remove} doesn't exist.")
                                continue
                            else:
                                raise e
                    except Exception as e:
                        errors['extra'] += 1
                        logger.debug2(f"Error removing file '{file_to_remove}': {e}")
                        continue

        # Once files are deleted, check and remove subdirectories which are now empty, as specified in cluster.json.
        directories_to_check = (os.path.dirname(f) for f, data in ko_files['extra'].items()
                                if cluster_items['files'][data['cluster_item_key']]['remove_subdirs_if_empty'])
        for directory in directories_to_check:
            try:
                full_path = os.path.join(common.wazuh_path, directory)
                dir_files = set(os.listdir(full_path))
                if not dir_files or dir_files.issubset(set(cluster_items['files']['excluded_files'])):
                    shutil.rmtree(full_path)
            except Exception as e:
                errors['extra'] += 1
                logger.debug2(f"Error removing directory '{directory}': {e}")
                continue

        if sum(errors.values()) > 0:
            logger.error(f"Found errors: {errors['shared']} overwriting, {errors['missing']} creating and "
                         f"{errors['extra']} removing")

    def get_logger(self, logger_tag: str = ''):
        """Get current logger. In workers it will always return the main logger.

        Parameters
        ----------
        logger_tag : str
            Logger tag to return.

        Returns
        -------
        Logger object
            A logger object.
        """
        return self.logger


class Worker(client.AbstractClientManager):
    """
    Initialize worker variables, connect to the master and run the DAPI request queue.
    """

    def __init__(self, **kwargs):
        """Class constructor.

        Parameters
        ----------
        kwargs
            Arbitrary keyword arguments to be sent as parameter to data_retriever callable.
        """
        self.task_pool = kwargs.pop('task_pool')
        super().__init__(**kwargs, tag="Worker")
        self.cluster_name = self.configuration['name']
        self.version = metadata.__version__
        self.node_type = self.configuration['node_type']
        self.handler_class = WorkerHandler
        self.extra_args = {'cluster_name': self.cluster_name, 'version': self.version, 'node_type': self.node_type}
        self.dapi = dapi.APIRequestQueue(server=self)
        self.integrity_control = {}

    def add_tasks(self) -> List[Tuple[asyncio.coroutine, Tuple]]:
        """Define the tasks that the worker will always run in an infinite loop.

        Returns
        -------
        List of tuples
            The first item is the coroutine to run and the second is the arguments it needs. In this case,
            all coroutines don't need arguments.
        """
        return super().add_tasks() + [(self.client.sync_integrity, tuple()), (self.client.sync_agent_info, tuple()),
                                      (self.dapi.run, tuple())]

    def get_node(self) -> Dict:
        """Get basic information about the worker node. Used in the GET/cluster/node API call.

        Returns
        -------
        dict
            Basic node information.
        """
        return {'type': self.configuration['node_type'], 'cluster': self.configuration['name'],
                'node': self.configuration['node_name']}
