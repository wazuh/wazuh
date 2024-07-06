# Created by elwali10 <walikarkoub@gmail.com>.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.
#
# ossec.conf configuration structure
# <integration>
#  <name>discord</name>
#  <hook_url>https://discord.com/api/webhooks/hookID</hook_url> <!-- Replace with your discord hook URL -->
#  <level>3</level>
#  <alert_format>json</alert_format>
# </integration>

import sys
import json
import time
import requests
 
 
# Log messages to `integrations.log` file
def logger(message):
  f = open('/var/ossec/logs/integrations.log', 'a')
  f.write('{0} [Discord]: {1}\n'.format(time.strftime('%Y/%m/%d %H:%M:%S %Z'), message))
  f.close()

 
# Get alert json of alert file
def get_alert(alert_file):
  f = open(alert_file)
  alert_json = json.loads(f.read())
  f.close()
  return alert_json

# Generate Discord message
def generate_message(alert_json):
  level = alert_json['rule']['level']

  # Message color depending on alert rule level
  if level <= 5:
    color = 16776960 # yellow
  else:
    color = 15158332 # red
   
  embed_data = {}
  embed_data['title'] = alert_json['rule']['description'] if 'description' in alert_json['rule'] else 'N/A'
  embed_data['description'] = alert_json['full_log'] if 'full_log' in alert_json else ''
  embed_data['fields'] = []
 
  if 'agent' in alert_json:
    agent_text = '{0} (ID: {1})'.format(alert_json['agent']['name'], alert_json['agent']['id'])
    embed_data['fields'].append({
      'name' : 'Agent',
      'value' : '{0}'.format(agent_text),
      'inline' : True
    }) 
 
  embed_data['fields'].append({
    'name' : 'Rule ID',
    'value' : '{0} (Alert Level: {1})'.format(alert_json['rule']['id'], alert_json['rule']['level']),
    'inline' : True
  })
 
  if 'groups' in alert_json['rule'] and len(alert_json['rule']['groups']) > 0:
    embed_data['fields'].append({
      'name' : 'Group(s)',
      'value' : ', '.join(alert_json['rule']['groups']),
      'inline' : True
    })

  if 'mitre' in alert_json['rule']:
    embed_data['fields'].append({
      'name' : 'Mitre Tactic',
      'value' : '{0}'.format(alert_json['rule']['mitre']['tactic']),
      'inline' : True
    })
 
  if 'pci_dss' in alert_json['rule']:
    embed_data['fields'].append({
      'name' : 'PCI DSS',
      'value' : '{0}'.format(alert_json['rule']['pci_dss']),
      'inline' : True
    })

  if 'gdpr' in alert_json['rule']:
    embed_data['fields'].append({
      'name' : 'GDPR',
      'value' : '{0}'.format(alert_json['rule']['gdpr']),
      'inline' : True
    })

  embed_data['fields'].append({
    'name' : 'Location',
    'value' : alert_json['location'],
    'inline' : True
  })
 
  embed_data['color'] = color
  embed_data['timestamp'] = alert_json['timestamp']
 
  message = {'embeds': [ embed_data ] }
 
  return json.dumps(message)
 
# Send request to Discord webhook with the message
def send_message(message):
  headers = {'content-type': 'application/json', 'accept-charset': 'UTF-8'}
  response = requests.post(discord_webhook_url, data=message, headers=headers)
  logger(response)
 
if __name__ == '__main__':
  try:
    # Get arguments
    alert_file = sys.argv[1]
    discord_webhook_url = sys.argv[3]
 
    # Get alert from file and send message
    alert_json = get_alert(alert_file)
    message = generate_message(alert_json)
    send_message(message)
    sys.exit(0)
  except Exception as e:
    logger('ERROR: {0}'.format(str(e)))
    raise