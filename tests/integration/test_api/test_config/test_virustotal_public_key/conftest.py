# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest
import subprocess

from pathlib import Path
from . import WAZUH_PYTHON_INTERPRETER_PATH, MOCK_SERVER_PATH, MOCK_SERVER_IMAGE, MOCK_SERVER_CONTAINER


@pytest.fixture(scope="session")
def virustotal_mock_server_setup():
    """HTTPS mock server setup to avoid connection to virustotal.com."""
    hosts_modification_command = r"sed -i '/^$/i\I127.0.0.1 www.virustotal.com' /etc/hosts"
    iptables_command = 'sudo iptables -t nat -A OUTPUT -p tcp --dport 443 -d www.virustotal.com ' \
                       '-j REDIRECT --to-port 8080'
    docker_build_command = f"docker build -t {MOCK_SERVER_IMAGE} {MOCK_SERVER_PATH}"
    docker_run_command = f"docker container run -d -p 8080:8080 --name {MOCK_SERVER_CONTAINER} {MOCK_SERVER_IMAGE}"

    try:
        # Modify /etc/hosts
        subprocess.run(hosts_modification_command, shell=True)

        # Set Up Port Forwarding with iptables
        subprocess.run(iptables_command, shell=True)

        # Build HTTPS mock server image
        subprocess.run(docker_build_command, shell=True)

        # Run the HTTPS mock server in the background
        subprocess.run(docker_run_command, shell=True)

    except Exception as e:
        print(f'Error setting up the HTTPS mock server: {str(e)}')
        raise

    yield

    subprocess.run(f"docker container stop {MOCK_SERVER_CONTAINER}", shell=True)
    subprocess.run(f"docker container rm {MOCK_SERVER_CONTAINER}", shell=True)


@pytest.fixture
def disable_ssl_verification():
    """Modify wazuh/core/utils.py to avoid SSL certificate verification."""
    file_path = Path(WAZUH_PYTHON_INTERPRETER_PATH, '/wazuh/core/utils.py')
    sed_command = r"sed -i 's/\(virustotal_response = get(url=url, headers=headers, timeout=10\))/\1, verify=False)/'"

    # Construct the complete command
    command = f"{sed_command} {file_path}"

    try:
        # Modify utils.py and disable SSL certificate verification
        result = subprocess.run(command, capture_output=True, text=True, shell=True)
    except Exception as e:
        print(f'Error executing command to disable ssl verification: {str(e)} {result.stderr}')
