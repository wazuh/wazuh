import json
import os
import re
import socket
import time

# Configuration
PROTOCOL = 'https'
HOST = 'localhost'
PORT = '55000'
USER = 'testing'
PASSWORD = 'wazuh'

# Variables
LOGIN_METHOD = 'POST'
BASE_URL = f'{PROTOCOL}://{HOST}:{PORT}'
LOGIN_URL = f'{BASE_URL}/security/user/authenticate'

HEALTHCHECK_TOKEN_FILE = '/tmp_volume/healthcheck/healthcheck.token'
OSSEC_LOG_PATH = '/var/ossec/logs/ossec.log'

# Variable used to compare default daemons_check.txt with an output with cluster disabled
CHECK_CLUSTERD_DAEMON = '1c1\n< wazuh-clusterd not running...\n---\n> wazuh-clusterd is running...\n'


def get_login_header(user, password):
    from base64 import b64encode

    basic_auth = f'{user}:{password}'.encode()
    return {'Authorization': f'Basic {b64encode(basic_auth).decode()}'}


def get_response(request_method, url, headers):
    """Make a Wazuh API request and get its response.

    Parameters
    ----------
    request_method : str
        Request method to be used in the API request.
    url : str
        URL of the API (+ endpoint and parameters if needed).
    headers : dict
        Headers required by the API.

    Returns
    -------
    Dict
        API response for the request.
    """
    import requests
    import urllib3

    # Disable insecure https warnings (for self-signed SSL certificates)
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    request_result = getattr(requests, request_method.lower())(url, headers=headers, verify=False)

    if request_result.status_code == 200:
        return json.loads(request_result.content.decode())


def get_agent_health_base():
    # Get agent health. The agent will be healthy if it has been connected to the manager after been
    # restarted due to shared configuration changes.
    # Using agentd when using grep as the module name can vary between ossec-agentd and wazuh-agentd,
    # depending on the agent version.

    shared_conf_restart = os.system(
        f"grep -q 'agentd: INFO: Agent is restarting due to shared configuration changes.' {OSSEC_LOG_PATH}"
    )
    agent_connection = os.system(f"grep -q 'agentd: INFO: (4102): Connected to the server' {OSSEC_LOG_PATH}")

    if shared_conf_restart == 0 and agent_connection == 0:
        # No -q option as we need the output
        output = (
            os.popen(
                f"grep -a 'agentd: INFO: Agent is restarting due to shared configuration changes."
                f"\|agentd: INFO: (4102): Connected to the server' {OSSEC_LOG_PATH}"
            )
            .read()
            .split('\n')[:-1]
        )

        agent_restarted = False
        for log in output:
            if not agent_restarted and re.match(r'.*Agent is restarting due to shared configuration changes.*', log):
                agent_restarted = True
            if agent_restarted and re.match(r'.*Connected to the server.*', log):
                # Wait to avoid the worst case scenario:
                # +10 seconds for the agent to report to the worker
                # +10 seconds for the worker to report to the master
                # +10 seconds for the shared configuration to be synced
                # After this time, the agent appears as active and synced in the master node
                time.sleep(30)
                return 0
    return 1


def check(result):
    if result == 0:
        return 0
    else:
        return 1


def get_master_health(env_mode):
    os.system('/var/ossec/bin/agent_control -ls > /tmp_volume/output.txt')
    os.system('/var/ossec/bin/wazuh-control status > /tmp_volume/daemons.txt')

    check0 = check(os.system('diff -q /tmp_volume/output.txt /tmp_volume/healthcheck/agent_control_check.txt'))
    check1 = check(os.system('diff -q /tmp_volume/daemons.txt /tmp_volume/healthcheck/daemons_check.txt'))
    check2 = get_api_health()

    return check0 or check1 or check2


def get_worker_health():
    os.system('/var/ossec/bin/wazuh-control status > /tmp_volume/daemons.txt')
    return check(os.system('diff -q /tmp_volume/daemons.txt /tmp_volume/healthcheck/daemons_check.txt'))


def get_manager_health_base(env_mode):
    return get_master_health(env_mode=env_mode) if socket.gethostname() == 'wazuh-master' else get_worker_health()


def get_api_health():
    if not os.path.exists(HEALTHCHECK_TOKEN_FILE):
        if get_response(LOGIN_METHOD, LOGIN_URL, get_login_header(USER, PASSWORD)):
            open(HEALTHCHECK_TOKEN_FILE, mode='w').close()
            return 0
        else:
            return 1
    else:
        return 0
