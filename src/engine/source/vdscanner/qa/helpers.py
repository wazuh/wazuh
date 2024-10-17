# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import time
import re
from pathlib import Path


def clean_env():
    # Delete previous inventory directory if exists
    if Path("queue/vd/inventory").exists():
        for file in Path("queue/vd/inventory").glob("*"):
            file.unlink()
        Path("queue/vd/inventory").rmdir()

    # Remove previous log file if exists
    if Path("log.out").exists():
        Path("log.out").unlink()


def set_command():
    # Set the path to the binary
    cmd = Path("engine/build/source/vdscanner/tool/", "vdscanner_testtool")
    cmd_alt = Path("engine/source/vdscanner/tool/", "vdscanner_testtool")

    # Ensure the binary exists
    if not cmd.exists():
        cmd = cmd_alt
    assert cmd.exists(), "The binary does not exists"

    args = ["-l", "log.out",
            "-s", "test.sock"]

    return ([cmd] + args)
