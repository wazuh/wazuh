# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import asyncio
import errno
import os
import shutil
from typing import Tuple, Dict
from wazuh.cluster import client, cluster, common as c_common
from wazuh import common


class WorkerHandler(client.AbstractClient):

    def __init__(self, **kwargs):
        super().__init__(**kwargs, tag="Worker")

    def process_request(self, command: bytes, data: bytes) -> Tuple[bytes, bytes]:
        self.logger.debug("Command received: '{}'".format(command))
        if command == b'sync_m_c_ok':
            return b'ok', b'Thanks'
        elif command == b'sync_m_c':
            return self.setup_receive_files_from_master()
        elif command == b'sync_m_c_e':
            return self.end_receiving_integrity(data.decode())
        else:
            return super().process_request(command, data)

    def setup_receive_files_from_master(self):
        my_task = c_common.TaskWithId(self.process_files_from_master)
        self.sync_tasks[my_task.name] = my_task
        return b'ok', str(my_task).encode()

    def end_receiving_integrity(self, task_and_file_names: str) -> Tuple[bytes, bytes]:
        task_name, filename = task_and_file_names.split(' ', 1)
        self.sync_tasks[task_name].filename = filename
        self.sync_tasks[task_name].received_information.set()
        return b'ok', b'Updating files from master'

    async def sync_integrity(self):
        while True:
            await asyncio.sleep(5)
            self.logger.info("Synchronizing integrity.")
            # ask for permission
            result = await self.send_request(command=b'sync_i_w_m_p', data=b'')
            if result.startswith(b'Error'):
                self.logger.error(b"Error asking for permission: " + result)
                continue
            elif result == b'False':
                self.logger.info("Master didn't grant permission to synchronize integrity")
                continue
            else:
                self.logger.info("Permission granted. Synchronizing integrity.")

            # Job: synchronize master files
            cluster_control = {'master_files': cluster.get_files_status('master'), 'worker_files': None}

            self.logger.info("Compressing files")
            compressed_data_path = cluster.compress_files(name=self.name, list_path=None,
                                                          cluster_control_json=cluster_control)
            task_id = await self.send_request(command=b'sync_i_w_m', data=b'')

            self.logger.info("Sending file to master")
            result = await self.send_file(filename=compressed_data_path)
            if result.startswith(b'Error'):
                self.logger.error(b"Error sending worker files information: " + result)
            else:
                self.logger.info("Worker files integrity sent to master.")

            result = await self.send_request(command=b'sync_i_w_m_e', data=task_id + b' ' + compressed_data_path.encode())
            if result.startswith(b'Error'):
                self.logger.error(result)

    async def process_files_from_master(self, name: str, file_received: asyncio.Event):
        await file_received.wait()
        self.logger.info("Analyzing received files: Start.")

        ko_files, zip_path = cluster.decompress_files(self.sync_tasks[name].filename)
        self.logger.info("Analyzing received files: Missing: {}. Shared: {}. Extra: {}. ExtraValid: {}".format(
            len(ko_files['missing']), len(ko_files['shared']), len(ko_files['extra']), len(ko_files['extra_valid'])))

        # Update files
        if ko_files['extra_valid']:
            self.logger.info("Master requires some worker files. Not Implemented Yet.")

        if not ko_files['shared'] and not ko_files['missing'] and not ko_files['extra']:
            self.logger.info("Worker meets integrity checks. No actions.")
        else:
            self.logger.info("Worker does not meet integrity checks. Actions required.")
            self.logger.info("Updating files: Start.")
            self.update_master_files_in_worker(ko_files, zip_path)
            self.logger.info("Updating files: End.")

    def update_master_files_in_worker(self, ko_files: Dict, zip_path: str):
        def overwrite_or_create_files(filename, data, content=None):
            # Cluster items information: write mode and umask
            cluster_item_key = data['cluster_item_key']
            w_mode = cluster_items[cluster_item_key]['write_mode']
            umask = cluster_items[cluster_item_key]['umask']

            if content is None:
                # Full path
                my_zip_path = "{}/{}".format(zip_path, filename)
                # File content and time
                with open(my_zip_path, 'r') as f:
                    file_data = f.read()
            else:
                file_data = content

            tmp_path = '/queue/cluster/tmp_files'

            cluster._update_file(file_path=filename, new_content=file_data, umask_int=umask, w_mode=w_mode,
                                 tmp_dir=tmp_path, whoami='worker')

        cluster_items = cluster.get_cluster_items()['files']
        for filetype, files in ko_files.items():
            if filetype == 'shared' or filetype == 'missing':
                self.logger.debug("Received {} {} files to update from master.".format(len(ko_files[filetype]),
                                                                                       filetype))
                for filename, data in files.items():
                    try:
                        self.logger.debug2("Processing file {}".format(filename))
                        if data['merged']:
                            for name, content, _ in cluster.unmerge_agent_info('agent-groups', zip_path, filename):
                                overwrite_or_create_files(name, data, content)
                        else:
                            overwrite_or_create_files(filename, data)
                    except Exception as e:
                        self.logger.debug2("Error processing {} file '{}': {}".format(filetype, filename, e))
                        continue
            else:
                for file_to_remove in files:
                    try:
                        self.logger.debug2("Remove file: '{}'".format(file_to_remove))
                        file_path = common.ossec_path + file_to_remove
                        try:
                            os.remove(file_path)
                        except OSError as e:
                            if e.errno == errno.ENOENT and '/queue/agent-groups/' in file_path:
                                self.logger.debug2("File {} doesn't exist.".format(file_to_remove))
                                continue
                            else:
                                raise e
                    except Exception as e:
                        self.logger.debug2("Error removing file '{}': {}".format(file_to_remove, str(e)))
                        continue

            directories_to_check = (os.path.dirname(f) for f, data in ko_files['extra'].items()
                                    if cluster_items[data['cluster_item_key']]['remove_subdirs_if_empty'])
            for directory in directories_to_check:
                try:
                    full_path = common.ossec_path + directory
                    dir_files = set(os.listdir(full_path))
                    if not dir_files or dir_files.issubset(set(cluster_items['excluded_files'])):
                        shutil.rmtree(full_path)
                except Exception as e:
                    self.logger.debug2("Error removing directory '{}': {}".format(directory, str(e)))
                    continue


class Worker(client.AbstractClientManager):

    def __init__(self, **kwargs):
        super().__init__(**kwargs, tag="Worker manager")
        self.handler_class = WorkerHandler

    def add_tasks(self):
        return super().add_tasks() + [(self.client.sync_integrity, tuple())]
