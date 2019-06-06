#!/usr/bin/env python

# Analyze the aws-eventnames cdb list against multiple sources of CloudTrail actions
#   1) IAM events from PolicyUniverse (https://github.com/Netflix-Skunkworks/policyuniverse).
#   2) CloudTrail events from CloudTracker (https://github.com/duo-labs/cloudtracker)
#  Use this to make recommendations for correcting existing entries, or to suggest new additions
#
# Copyright (C) 2015-2019, Wazuh Inc.
# Copyright: GPLv3
#
# By Jeremy Phillips <jeremy@uranusbytes.com>
#

import signal
import sys
import logging
import argparse
import requests
import json
from datetime import datetime

################################################################################
# Constants
###############################################################################
_DEFAULT_LOGGING_LEVEL = logging.INFO
URL_POLICYUNIVERSE_DATA = 'https://github.com/Netflix-Skunkworks/policyuniverse/raw/master/policyuniverse/data.json'
URL_CLOUDTRACKER_DATA = 'https://github.com/duo-labs/cloudtracker/raw/master/cloudtracker/data/cloudtrail_supported_actions.txt'
OUTPUT_HEADER = '''TEMPLATE-0: # Built using Wazuh tool /contrib/wodles/aws/build_aws_eventnames_cdb.py
TEMPLATE-1: # Data source: CloudTracker - https://github.com/duo-labs/cloudtracker/
TEMPLATE-2: # Data source: PolicyUniverse - https://github.com/Netflix-Skunkworks/policyuniverse/
TEMPLATE-3: # Last updated {date}
'''.format(date=datetime.now().isoformat())
BASELINE_EVENT_TYPES = {
  'ConsoleLogin': ['signin'],
  'ExitRole': ['signin'],
  'RenewRole': ['signin'],
  'SwitchRole': ['signin']
}
EXCLUDE_EVENT_TYPES = [
  'BatchGet',
  'Describe',
  'Get',
  'List',
  'Receive',
  'Scan',
  'Search',
  'Select',
  'SendMessage',
  'Simulate',
  'Test',
  'Validate',
  'Verify',
  'View',
]
IGNORE_EVENT_TYPES = [
  'TEMPLATE'
]


################################################################################
# Functions
###############################################################################
def _signal_handler(signal, frame):
  print("ERROR: SIGINT received.")
  sys.exit(2)
  return


def _get_script_arguments():
  parser = argparse.ArgumentParser(usage="usage: %(prog)s [options]",
                                   description="Analyze aws eventnames cdb",
                                   formatter_class=argparse.RawTextHelpFormatter)
  parser.add_argument('-c', '--cdb', dest='path_cdb', help='Path to AWS eventnames cdb',
                      action='store', default='/var/ossec/etc/lists/amazon/aws-eventnames')
  parser.add_argument('-u', '--newcdb', dest='path_newcdb', action='store',
                      help='Path to new AWS eventnames cdb', default=None)
  parser.add_argument('-iu', '--includeunknown', dest='include_unknown', action='store_true',
                      help='Include unknown actions in new AWS eventnames cdb', default=False)
  parser.add_argument('-pu', '--policyuniverse', dest='path_policyuniverse', action='store',
                      help='Local path to policy universe data file (otherwise download)', default=None)
  parser.add_argument('-ct', '--cloudtracker', dest='path_cloudtracker', action='store',
                      help='Path to cloud tracker data file (otherwise download)', default=None)
  parser.add_argument('-d', '--debug', action='store_true', dest='debug', default=False, help='Enable debug')
  return parser.parse_args()


def _get_cloudtracker(options):
  _cloudtracker_actions = {}
  _logger.debug('Gather CloudTracker actions')
  if options.path_cloudtracker is not None:
    _logger.info('Loading CloudTracker from local file')
    try:
      _file = open(options.path_cloudtracker, 'r')
      _cloudtrail_file = '\n'.join(_file.readlines())
    except:
      _logger.error('Failed to open local CloudTracker data file')
      exit(1)
  else:
    _logger.info('Loading CloudTracker data from github')
    try:
      _response = requests.post(URL_CLOUDTRACKER_DATA)
      _cloudtrail_file = _response.text
    except:
      _logger.error('Failed to download CloudTracker data from github')
      exit(1)

  _logger.info('Parse CloudTracker data')
  for _line in _cloudtrail_file.splitlines():
    _event = _line.split(':')
    if len(_event) != 2:
      _logger.debug('Line not in expected format, or empty')
      continue
    if _event[1] in IGNORE_EVENT_TYPES:
      _logger.debug('Event type ignored')
      continue
    _flag_not_found = True
    for _event_type in EXCLUDE_EVENT_TYPES:
      if _event[1][:len(_event_type)] == _event_type:
        # Event type is excluded
        _flag_not_found = False
        break

    _logger.debug('Event type not excluded; add to final list')
    if _flag_not_found:
      if _event[1] in _cloudtracker_actions:
        _cloudtracker_actions[_event[1]].append(_event[0])
      else:
        _cloudtracker_actions[_event[1]] = [_event[0]]

  return _cloudtracker_actions


def _get_policyuniverse(options):
  _policyuniverse_actions = {}
  _logger.info('Gather PolicyUniverse actions')
  if options.path_policyuniverse is not None:
    _logger.info('Loading PolicyUniverse from local file')
    try:
      _json_file = open(options.path_policyuniverse, 'r')
      _policyuniverse_json = json.load(_json_file)
    except:
      _logger.error('Failed to open local PolicyUniverse data file')
      exit(1)
  else:
    _logger.info('Loading PolicyUniverse data from github')
    try:
      _response = requests.post(URL_POLICYUNIVERSE_DATA)
      _policyuniverse_json = json.loads(_response.text)
    except:
      _logger.error('Failed to download PolicyUniverse data from github')
      exit(1)

  _logger.info('Parse PolicyUniverse data')

  for _aws_service in _policyuniverse_json:
    for _service_action in _policyuniverse_json[_aws_service]['actions']:
      if _service_action in IGNORE_EVENT_TYPES:
        _logger.debug('Event type ignored')
        continue
      _flag_not_found = True
      for _event_type in EXCLUDE_EVENT_TYPES:
        if _service_action[:len(_event_type)] == _event_type:
          # Event type is excluded
          _flag_not_found = False
          break
      _logger.debug('Event type not excluded; add to final list')
      if _flag_not_found:
        if _service_action in _policyuniverse_actions:
          _policyuniverse_actions[_service_action].append(_policyuniverse_json[_aws_service]['prefix'])
        else:
          _policyuniverse_actions[_service_action] = [_policyuniverse_json[_aws_service]['prefix']]

  return _policyuniverse_actions


def _get_logger(options):
  _logger = logging.getLogger()
  _logger.setLevel(logging.NOTSET)
  _logging_format = logging.Formatter(fmt='[%(asctime)s] %(levelname)s - %(message)s')
  # If debug enabled
  if options.debug:
    _logging_level = logging.DEBUG
  else:
    _logging_level = _DEFAULT_LOGGING_LEVEL
  # Setup logging to stdout
  _stdout_handler = logging.StreamHandler(stream=sys.stdout)
  _stdout_handler.setLevel(_logging_level)
  _stdout_handler.setFormatter(_logging_format)
  _logger.addHandler(_stdout_handler)
  return _logger


def _get_cdb(options):
  _logger.info('Loading aws eventnames cdb file')
  try:
    _file = open(options.path_cdb, 'r')
    _cdb_file = _file.readlines()
  except:
    _logger.error('Failed to aws eventnames cdb file')
    exit(1)
  _cdb = {}
  for _line in _cdb_file:
    _line_parts = _line.strip().split(':')
    _cdb[_line_parts[0]] = _line_parts[1].split(',')
  return _cdb

def _get_cloudtrail_actions(options):
  _cloudtracker = _get_cloudtracker(options)
  _policyuniverse = _get_policyuniverse(options)

  _cloudtrail_actions = _policyuniverse
  for _action in _cloudtracker:
    if _action not in _cloudtrail_actions:
      _cloudtrail_actions[_action] = _cloudtracker[_action]
    else:
      for _service in _cloudtracker[_action]:
        if _service not in _cloudtrail_actions[_action]:
          _cloudtrail_actions[_action].append(_service)

  return _cloudtrail_actions


def _analyze_unknown_actions(existing_cdb, cloudtrail_actions):
  _logger.info('Analyze old cdb for unknown actions')
  _unknown_actions = []
  for _action in existing_cdb:
    if _action not in cloudtrail_actions and _action not in IGNORE_EVENT_TYPES and _action not in BASELINE_EVENT_TYPES:
      _flag_not_found = True
      for _event_type in EXCLUDE_EVENT_TYPES:
        if _action[:len(_event_type)] == _event_type:
          # Event type is excluded
          _flag_not_found = False
          break
      if _flag_not_found:
        _unknown_actions.append(_action)
        _logger.warning('Unknown action found in old cdb: {0}'.format(_action))
  return _unknown_actions


def _build_new_cdb(cloudtrail_actions, existing_cdb, unknown_actions, options):
  _logger.info('Build new cdb list')
  _cdb_actions = []

  _logger.debug('Add events from online sources')
  for _action in cloudtrail_actions:
    _cdb_actions.append('{0}:{1}'.format(_action, ','.join(cloudtrail_actions[_action])))

  _logger.debug('Add events from baseline events')
  for _action in BASELINE_EVENT_TYPES:
    _cdb_actions.append('{0}:{1}'.format(_action, ','.join(BASELINE_EVENT_TYPES[_action])))

  if options.include_unknown:
    _logger.debug('Add unknown events from old cdb')
    for _action in unknown_actions:
      if _action not in IGNORE_EVENT_TYPES:
        _cdb_actions.append('{0}:{1}'.format(_action, ','.join(existing_cdb[_action])))
  return _cdb_actions


def _save_cdb(new_cdb, options):
  _logger.info('Save new cdb file')
  try:
    with open(options.path_newcdb, 'w') as _cdb_file:
      _cdb_file.write('{0}{1}'.format(OUTPUT_HEADER, '\n'.join(sorted(new_cdb))))
  except:
    _logger.error('Unable to save new cdb file')
    exit(1)
  return

################################################################################
# Main
###############################################################################
def _main():
  # Setup logging
  global _logger

  # Parse script arguments
  _options = _get_script_arguments()
  _logger = _get_logger(_options)

  _logger.info('Script: Create new cdb list for aws event names')

  # Load data
  _existing_cdb = _get_cdb(_options)
  _cloudtrail_actions = _get_cloudtrail_actions(_options)

  # Analyze data
  _unknown_actions = _analyze_unknown_actions(_existing_cdb, _cloudtrail_actions)

  # Build new cdb
  if _options.path_newcdb is not None:
    _new_cdb = _build_new_cdb(_cloudtrail_actions, _existing_cdb, _unknown_actions, _options)
    _save_cdb(_new_cdb, _options)

  _logger.info('Script finished')

  return


if __name__ == '__main__':
  try:
    signal.signal(signal.SIGINT, _signal_handler)
    _main()
    sys.exit(0)
  except Exception as err:
    print("Unknown error: {}".format(err))
    raise
    sys.exit(1)
