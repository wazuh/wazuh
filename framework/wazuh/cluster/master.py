# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import asyncio
import fnmatch
import os
import random
from typing import Tuple
from wazuh.cluster import server, cluster, common as c_common
from wazuh import common, utils


class MasterHandler(server.AbstractServerHandler):

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
        my_task = c_common.TaskWithId(self.sync_integrity)
        self.sync_tasks[my_task.name] = my_task
        return b'ok', str(my_task).encode()

    def end_receiving_integrity_checksums(self, task_and_file_names: str) -> Tuple[bytes, bytes]:
        task_name, filename = task_and_file_names.split(' ', 1)
        self.sync_tasks[task_name].filename = filename
        self.sync_tasks[task_name].received_information.set()
        return b'ok', b'Checking worker integrity'

    async def sync_integrity(self, task_name: str, received_file: asyncio.Task):
        self.logger.info("Waiting to receive zip file from worker")
        await received_file.wait()
        self.logger.info("File received")

        json_file, zip_dir_path = cluster.decompress_files(self.sync_tasks[task_name].filename)

        self.logger.info("Analyzing worker integrity: Received {} files to check.".format(len(json_file['master_files'])))

        worker_files_ko = cluster.compare_files(self.server.integrity_control, json_file['master_files'])
        agent_groups_to_merge = {key: fnmatch.filter(values.keys(), '*/agent-groups/*') for key, values in
                                 worker_files_ko.items()}
        merged_files = {key: cluster.merge_agent_info(merge_type='agent-groups', files=values, file_type='-'+key,
                                                      time_limit_seconds=0)
                        for key, values in agent_groups_to_merge.items()}
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

        if len(list(filter(lambda x: x == {}, worker_files_ko.values()))) == len(worker_files_ko):
            self.logger.info("Analyzing worker integrity: Files checked. There are no KO files.")
            result = await self.send_request(command=b'sync_m_c_ok', data=b'')

        else:
            self.logger.info("Analyzing worker integrity: Files checked. There are KO files.")

            # Compress data: master files (only KO shared and missing)
            self.logger.debug("Analyzing worker integrity: Files checked. Compressing KO files.")

            master_files_paths = [item for item in worker_files_ko['shared']]
            master_files_paths.extend([item for item in worker_files_ko['missing']])

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
