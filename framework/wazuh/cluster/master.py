# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import asyncio
import functools
import operator
import os
from typing import Tuple
from wazuh.cluster import server, cluster, common as c_common
from wazuh import common, utils


class MasterHandler(server.AbstractServerHandler, c_common.WazuhCommon):

    def __init__(self, **kwargs):
        super().__init__(**kwargs, tag="Worker")
        self.sync_integrity_free = True  # the worker isn't currently synchronizing integrity

    def process_request(self, command: bytes, data: bytes) -> Tuple[bytes, bytes]:
        self.logger.debug("Command received: {}".format(command))
        if command == b'sync_i_w_m_p':
            return self.get_permission_sync_integrity()
        elif command == b'sync_i_w_m':
            return self.setup_sync_integrity()
        elif command == b'sync_i_w_m_e':
            return self.end_receiving_integrity_checksums(data.decode())
        else:
            return super().process_request(command, data)

    def hello(self, data: bytes) -> Tuple[bytes, bytes]:
        cmd, payload = super().hello(data)
        worker_dir = '{}/queue/cluster/{}'.format(common.ossec_path, self.name)
        if cmd == b'ok' and not os.path.exists(worker_dir):
            utils.mkdir_with_mode(worker_dir)
        return cmd, payload

    def get_permission_sync_integrity(self) -> Tuple[bytes, bytes]:
        return b'ok', str(self.sync_integrity_free).encode()

    def setup_sync_integrity(self) -> Tuple[bytes, bytes]:
        self.sync_integrity_free = False
        return super().setup_receive_file(self.sync_integrity)

    def end_receiving_integrity_checksums(self, task_and_file_names: str) -> Tuple[bytes, bytes]:
        return super().end_receiving_file(task_and_file_names)

    async def sync_integrity(self, task_name: str, received_file: asyncio.Task):
        self.logger.info("Waiting to receive zip file from worker")
        await received_file.wait()
        received_filename = self.sync_tasks[task_name].filename
        self.logger.debug("Received file from worker: '{}'".format(received_filename))

        files_checksums, decompressed_files_path = cluster.decompress_files(received_filename)
        self.logger.info("Analyzing worker integrity: Received {} files to check.".format(len(files_checksums)))

        # classify files in shared, missing, extra and extra valid.
        worker_files_ko = cluster.compare_files(self.server.integrity_control, files_checksums)
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
                return task_name

            result = await self.send_file(compressed_data)
            if result.startswith(b'Error'):
                return result

            result = await self.send_request(command=b'sync_m_c_e', data=task_name + b' ' + compressed_data.encode())
        self.sync_integrity_free = True
        return result


class Master(server.AbstractServer):

    def __init__(self, **kwargs):
        super().__init__(**kwargs, tag="Master")
        self.integrity_control = {}
        self.tasks.append(self.file_status_update)
        self.handler_class = MasterHandler

    async def file_status_update(self):
        while True:
            self.logger.debug("Calculating file integrity.")
            try:
                self.integrity_control = cluster.get_files_status('master')
            except Exception as e:
                self.logger.error("Error calculating file integrity: {}".format(e))
            self.logger.debug("File integrity calculated.")

            await asyncio.sleep(30)
