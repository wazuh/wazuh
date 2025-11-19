# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from api.models.base_model_ import Body


class ContentUpsertModel(Body):
    def __init__(
        self,
        content: str = None,
    ):
        self.swagger_types = {"content": str}

        self.attribute_map = {"content": "content"}

        self._content = content

    @property
    def content(self):
        return self._content

    @content.setter
    def content(self, content):
        self._content = content
