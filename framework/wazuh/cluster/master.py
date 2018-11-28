# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import asyncio
import os
from typing import Tuple
from wazuh.cluster import server, cluster
from wazuh import common, utils


class MasterHandler(server.AbstractServerHandler):

    def __init__(self, **kwargs):
        super().__init__(**kwargs, tag="Worker")

    def hello(self, data: bytes) -> Tuple[bytes, bytes]:
        cmd, payload = super().hello(data)
        worker_dir = '{}/queue/cluster/{}'.format(common.ossec_path, self.name)
        if cmd == b'ok' and not os.path.exists(worker_dir):
            utils.mkdir_with_mode(worker_dir)
        return cmd, payload



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
