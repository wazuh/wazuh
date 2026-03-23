# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from services import aws_service
from services import cloudwatchlogs
from services import inspector

__all__ = [
  "aws_service",
  "cloudwatchlogs",
  "inspector"
]
