# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import asyncio
from wazuh.cluster import client, cluster


class WorkerHandler(client.AbstractClient):

    def __init__(self, **kwargs):
        super().__init__(**kwargs, tag="Worker")

    async def sync_integrity(self):
        while True:
            await asyncio.sleep(30)
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
            result = await self.send_request(command=b'sync_i_w_m', data=b'')

            self.logger.info("Sending file to master")
            result = await self.send_file(filename=compressed_data_path)
            if result.startswith(b'Error'):
                self.logger.error(b"Error sending worker files information: " + result)
            else:
                self.logger.info("Worker files integrity sent to master.")

            result = await self.send_request(command=b'sync_i_w_m_e', data=b'')


class Worker(client.AbstractClientManager):

    def __init__(self, **kwargs):
        super().__init__(**kwargs, tag="Worker manager")
        self.handler_class = WorkerHandler

    def add_tasks(self):
        return super().add_tasks() + [(self.client.sync_integrity, tuple())]
