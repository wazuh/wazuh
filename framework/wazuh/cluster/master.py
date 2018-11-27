# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import asyncio
from wazuh.cluster import server, cluster


class Master(server.AbstractServer):

    def __init__(self, *args):
        super().__init__(*args, tag="Master")
        self.integrity_control = {}
        self.tasks.append(self.file_status_update)

    async def file_status_update(self):
        while True:
            self.logger.debug("Calculating file integrity.")
            try:
                self.integrity_control = cluster.get_files_status('master')
            except Exception as e:
                self.logger.error("Error calculating file integrity: {}".format(e))
            self.logger.debug("File integrity calculated.")

            await asyncio.sleep(30)
