#!/usr/bin/env python
#
# Authored by Jeremy Phillips <jeremy@uranusbytes.com>
# Copyright: GPLv3
#
# Wrapper around prowler script to parse results and forward to Wazuh
# Prowler - https://github.com/toniblyx/prowler
#
# TODO: Add ability to disable different groups (EXTRA, etc...
# TODO: Allow to disable individual checks
# TODO: Remove all the commented out stuff
#
# Error Codes:
#   1 - Unknown
#   2 - SIGINT
#   3 - Error output from execution of Prowler
#   4 - Output row is invalid json
#   5 - Wazuh must be running
#   6 - Error sending to socket


import signal
import sys
import socket
import argparse
import subprocess
import json
from datetime import datetime
import os
import re

################################################################################
# Constants
################################################################################
WAZUH_PATH = open('/etc/ossec-init.conf').readline().split('"')[1]
DEBUG_LEVEL = 1  # Enable/disable debug mode
PATH_TO_PROWLER = '{0}/integrations/prowler'.format(WAZUH_PATH)  # No trailing slash
TEMPLATE_CHECK = '''
{{
  "integration": "prowler",
  "prowler": {0}
}}
'''
TEMPLATE_MSG = '1:Wazuh-Prowler:{0}'
TEMPLATE_ERROR = '''{{
  "aws_account_id": {aws_account_id},
  "aws_profile": "{aws_profile}",
  "prowler_error": "{prowler_error}",
  "prowler_version": "{prowler_version}",
  "timestamp": "{timestamp}",
  "status": "Error"
}}
'''
WAZUH_QUEUE = '{0}/queue/ossec/queue'.format(WAZUH_PATH)
FIELD_REMAP = {
  "Profile": "aws_profile",
  "Control": "control",
  "Account Number": "aws_account_id",
  "Level": "level",
  "Account Alias": "aws_account_alias",
  "Timestamp": "timestamp",
  "Region": "region",
  "Control ID": "control_id",
  "Status": "status",
  "Scored": "scored",
  "Message": "message"
}
CHECKS_FILES_TO_IGNORE = [
  'check_sample'
]


################################################################################
# Functions
################################################################################
def _send_msg(msg):
  try:
    _json_msg = json.dumps(_reformat_msg(msg))
    _debug("Sending Msg: {0}".format(_json_msg), 3)
    _socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    _socket.connect(WAZUH_QUEUE)
    _socket.send(TEMPLATE_MSG.format(_json_msg).encode())
    _socket.close()
  except socket.error as e:
    if e.errno == 111:
      print('ERROR: Wazuh must be running.')
      sys.exit(5)
    else:
      print("ERROR: Error sending message to wazuh: {}".format(e))
      sys.exit(6)
  except Exception as e:
    print("ERROR: Error sending message to wazuh: {}".format(e))
    sys.exit(6)
  return


def _handler(signal, frame):
  print("ERROR: SIGINT received.")
  sys.exit(12)


def _debug(msg, msg_level):
  if DEBUG_LEVEL >= msg_level:
    print('DEBUG-{level}: {debug_msg}'.format(level=msg_level, debug_msg=msg))


def _get_script_arguments():
  _parser = argparse.ArgumentParser(usage="usage: %(prog)s [options]",
                                    description="Wazuh wodle for evaluating AWS security configuration",
                                    formatter_class=argparse.RawTextHelpFormatter)
  _parser.add_argument('-c', '--aws_account_id', dest='aws_account_id',
                       help='AWS Account ID for logs',
                       required=False)
  _parser.add_argument('-d', '--debug', action='store', dest='debug', default=0, help='Enable debug')
  _parser.add_argument('-p', '--aws_profile', dest='aws_profile', help='The name of credential profile to use',
                       default=None)
  _parser.add_argument('-n', '--aws_account_alias', dest='aws_account_alias',
                       help='AWS Account ID Alias', default='')
  _parser.add_argument('-e', '--skip_on_error', action='store_false', dest='skip_on_error',
                       help='If check output is invalid json, error out instead of skipping the check', default=True)
  return _parser.parse_args()


def _run_prowler(prowler_args):
  _debug('Running prowler with args: {0}'.format(prowler_args), 1)
  _prowler_command = '{prowler}/prowler {args}'.format(prowler=PATH_TO_PROWLER, args=prowler_args)
  _debug('Running command: {0}'.format(_prowler_command), 2)
  _process = subprocess.Popen(_prowler_command, stdout=subprocess.PIPE, shell=True)
  _output, _error = _process.communicate()
  _debug('Raw prowler output: {0}'.format(_output), 3)
  _debug('Raw prowler error: {0}'.format(_error), 3)
  if _error is not None:
    _debug('PROWLER ERROR: {0}'.format(_error), 1)
    exit(3)
  return _output


def _get_prowler_version(options):
  _debug('+++ Get Prowler Version', 1)
  # Execute prowler, but only display the version and immediately exit
  return _run_prowler('-p {0} -V'.format(options.aws_profile)).rstrip()


def _get_prowler_results(options, prowler_check):
  _debug('+++ Get Prowler Results - {check}'.format(check=prowler_check), 1)
  # Execute prowler with all checks
  # -b = disable banner
  # -p = credential profile
  # -M = output json

  return _run_prowler('-b -c {check} -p {aws_profile} -M json'.format(check=prowler_check,
                                                                      aws_profile=options.aws_profile))

def _get_prowler_checks():
  _prowler_checks = []
  for _directory_path, _directories, _files in os.walk('{path}/checks'.format(path=PATH_TO_PROWLER)):
    _debug('Checking in : {}'.format(_directory_path), 3)
    for _file in _files:
      if _file in CHECKS_FILES_TO_IGNORE:
        _debug('Ignoring check - {}'.format(_directory_path, _file), 3)
      elif re.match("check\d+", _file):
        _prowler_checks.append(_file)
      elif re.match("check_extra(\d+)", _file):
        _prowler_checks.append(_file[6:])
      else:
        _debug('Unknown check file type- {}'.format(_directory_path, _file), 3)
  return _prowler_checks


def _send_prowler_results(prowler_results, _prowler_version, options):
  _debug('+++ Send Prowler Results', 1)
  for _check_result in prowler_results.splitlines():
    # Empty row
    if len(_check_result) < 1:
      continue
    # Something failed during prowler check
    elif _check_result[:17] == 'An error occurred':
      _debug('ERROR MSG --- {0}'.format(_check_result), 2)
      _temp_msg = TEMPLATE_ERROR.format(
        aws_account_id=options.aws_account_id,
        aws_profile=options.aws_profile,
        prowler_error=_check_result.replace('"', '\"'),
        prowler_version=_prowler_version,
        timestamp=datetime.now().isoformat()
      )
      _error_msg = json.loads(TEMPLATE_CHECK.format(_temp_msg))
      _send_msg(_error_msg)
      continue
    try:
      _debug('RESULT MSG --- {0}'.format(_check_result), 2)
      _check_result = json.loads(TEMPLATE_CHECK.format(_check_result))
    except:
      _debug('INVALID JSON --- {0}'.format(TEMPLATE_CHECK.format(_check_result)), 1)
      if not options.skip_on_error:
        exit(4)
    _check_result['prowler']['prowler_version'] = _prowler_version
    _check_result['prowler']['aws_account_alias'] = options.aws_account_alias
    _send_msg(_check_result)

  return True


def _reformat_msg(msg):
  for field in FIELD_REMAP:
    if field in msg['prowler']:
      msg['prowler'][FIELD_REMAP[field]] = msg['prowler'][field]
      del msg['prowler'][field]
  return msg


# Main
###############################################################################
def main(argv):
  _debug('+++ Begin script', 1)
  # Parse arguments
  _options = _get_script_arguments()

  if int(_options.debug) > 0:
    global DEBUG_LEVEL
    DEBUG_LEVEL = int(_options.debug)
    _debug('+++ Debug mode on - Level: {debug}'.format(debug=_options.debug), 1)

  _prowler_version = _get_prowler_version(_options)
  _prowler_checks = _get_prowler_checks()
  for _check in _prowler_checks:
    _prowler_results = _get_prowler_results(_options, _check)
    _send_prowler_results(_prowler_results, _prowler_version, _options)
  _debug('+++ Finished script', 1)
  return


if __name__ == '__main__':
  try:
    _debug('Args: {args}'.format(args=str(sys.argv)), 2)
    signal.signal(signal.SIGINT, _handler)
    main(sys.argv[1:])
    sys.exit(0)
  except Exception as e:
    print("Unknown error: {}".format(e))
    if DEBUG_LEVEL > 0:
      raise
    sys.exit(1)
