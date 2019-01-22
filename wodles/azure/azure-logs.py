#!/usr/bin/env python

 ###
 # Integration of Wazuh agent with Microsoft Azure
 # Copyright (C) 2015-2019, Wazuh Inc.
 #
 # This program is free software; you can redistribute it and/or modify
 # it under the terms of the GNU General Public License as published by
 # the Free Software Foundation; either version 2 of the License, or
 # (at your option) any later version.
 #
 ###

################################################################################################
# pip install azure
# https://github.com/Azure/azure-sdk-for-python
# https://docs.microsoft.com/en-us/azure/storage/blobs/storage-quickstart-blobs-python
################################################################################################

import logging
import time
import sys
import json
import os
import uuid
import datetime
import argparse
import hashlib
try:
	import requests
except Exception as e:
	print("Pytz is missing: '{}', try 'pip install requests'.".format(e))
	sys.exit(1)
try:
	import pytz
except Exception as e:
	print("Pytz is missing: '{}', try 'pip install pytz'.".format(e))
	sys.exit(1)
from os.path import dirname, abspath
from socket import socket, AF_UNIX, SOCK_DGRAM, SO_SNDBUF, SOL_SOCKET
from sys import argv
try:
	from azure.storage.blob import BlockBlobService
except Exception as e:
	print("Azure Storage SDK for Python is missing: '{}', try 'pip install azure-storage-blob'.".format(e))
	sys.exit(1)

ADDR = '/var/ossec/queue/ossec/queue'
BLEN = 212992

utc = pytz.UTC

################################################################################################
# Read and parser arguments.
################################################################################################

parser = argparse.ArgumentParser()
parser.add_argument("-v", "--verbose", action ='store_true', required = False, help ="Debug mode.")

### Log Analytics arguments ###
parser.add_argument("--log_analytics", action = 'store_true', required = False, help = "Activates Log Analytics API call.")
parser.add_argument("--la_id", metavar = 'ID', type = str, required = False, help = "Application ID for Log Analytics authentication.")
parser.add_argument("--la_key", metavar = "KEY", type = str, required = False, help = "Application Key for Log Analytics authentication.")
parser.add_argument("--la_auth_path", metavar = "filepath", type = str, required = False, help = "Path of the file containing the credentials for authentication.")
parser.add_argument("--la_tenant_domain", metavar = "domain", type = str, required = False, help = "Tenant domain for Log Analytics.")
parser.add_argument("--la_query", metavar = "query", type = str, required = False, help = "Query for Log Analytics.")
parser.add_argument("--workspace", metavar = "workspace", type = str, required = False, help = "Workspace for Log Analytics.")
parser.add_argument("--la_tag", metavar = "tag", type = str, required = False, help = "Tag that is added to the query result.")
parser.add_argument("--la_time_offset", metavar = "time", type = str, required = False, help = "Time range for the first request.")

### Graph arguments ###
parser.add_argument("--graph", action = 'store_true', required = False, help = "Activates Graph API call.")
parser.add_argument("--graph_id", metavar = 'ID', type = str, required = False, help = "Application ID for Graph authentication.")
parser.add_argument("--graph_key", metavar = "KEY", type = str, required = False, help = "Application KEY for Graph authentication.")
parser.add_argument("--graph_auth_path", metavar = "filepath", type = str, required = False, help = "Path of the file containing the credentials authentication.")
parser.add_argument("--graph_tenant_domain", metavar = "domain", type = str, required = False, help = "Tenant domain for Graph.")
parser.add_argument("--graph_query", metavar = "query", type = str, required = False, help = "Query for Graph.")
parser.add_argument("--graph_tag", metavar = "tag", type = str, required = False, help = "Tag that is added to the query result.")
parser.add_argument("--graph_time_offset", metavar = "time", type = str, required = False, help = "Time range for the first request.")

### Storage arguments ###
parser.add_argument("--storage", action = "store_true", required = False, help = "Activates Storage API call.")
parser.add_argument("--account_name", metavar = 'account', type = str, required = False, help = "Storage account name for authenticacion.")
parser.add_argument("--account_key", metavar = 'KEY', type = str, required = False, help = "Storage account key for authentication.")
parser.add_argument("--storage_auth_path", metavar = "filepath", type = str, required = False, help = "Path of the file containing the credentials authentication." )
parser.add_argument("--container", metavar = "container", type = str, required = False, help = "Name of the container where searchs the blobs.")
parser.add_argument("--blobs", metavar = "blobs", type = str, required = False, help = "Extension of blobs. For example: '*.log'")
parser.add_argument("--storage_tag", metavar = "tag", type = str, required = False, help = "Tag that is added to each blob request.")
parser.add_argument("--json_file", action = "store_true", required = False, help = "Specifies that the blob is only composed of events in json file format. By default, the content of the blob is considered to be plain text.")
parser.add_argument("--json_inline", action = "store_true", required = False, help = "Specifies that the blob is only composed of events in json inline format. By default, the content of the blob is considered to be plain text.")
parser.add_argument("--storage_time_offset", metavar = "time", type = str, required = False, help = "Time range for the first request.")

args = parser.parse_args()

if args.la_query:
	la_format_query = args.la_query.replace('"','')
if args.graph_query:
	graph_format_query = args.graph_query.replace("'","")
if args.container:
	container_format = args.container.replace('"','')
if args.blobs:
	blobs_format = args.blobs.replace('"','')

################################################################################################
# Gets the path to write logs.
################################################################################################

def get_log_path():

	path_result = ""
	ossec_init = open ('/etc/ossec-init.conf')
	for line in ossec_init:
		if "DIRECTORY=" in line:
			ossec_path = line.replace('DIRECTORY=','')
			half_path= ossec_path.replace('"','')
			path_result = half_path.replace('\n','')
	path_result = path_result + "/logs/azure_logs.log"
	return path_result


################################################################################################
# Configure the log settings.
################################################################################################

def set_logger():

	if args.verbose:
		logging.basicConfig(level = logging.DEBUG, format = '%(asctime)s %(levelname)s: AZURE %(message)s', datefmt = '%m/%d/%Y %I:%M:%S %p')
	else: 
		log_path = get_log_path()
		logging.basicConfig(filename=log_path, level = logging.DEBUG, format = '%(asctime)s %(levelname)s: AZURE %(message)s', datefmt = '%m/%d/%Y %I:%M:%S %p')


################################################################################################
# Checks if is the first time the script has been run. 
################################################################################################

def check_first_run():

	current_path = dirname(abspath(__file__)) 
	date_file = "/last_dates.json"
	path=current_path + date_file 

	if os.path.exists(current_path + date_file):
		return False
	else:
		# If the file does not exist, it will be created
		all_dates_content = {u'log_analytics':{}, u'graph':{}, u'storage':{}}
		try:
			with open(os.path.join(path), 'w') as file:
				json.dump(all_dates_content, file)
		except Exception as e:
			logging.error("Error: The file of the last dates could not be created. '{}'.".format(e))
		return True

################################################################################################
#Reads the arguments to check that at least one API is called.
################################################################################################

def read_arguments():

	check_arguments = False
	first_run = check_first_run()

	if args.log_analytics:
		start_log_analytics(first_run)
		check_arguments = True
	if args.graph:
		start_graph()
		check_arguments = True
	if args.storage:
		start_storage(first_run)
		check_arguments = True

	if check_arguments == False:
		logging.error("No API to connect to has been specified. Exit")
		sys.exit(1)

################################################################################################
# Read the authentication if it is given by file.
################################################################################################

def read_auth_path(auth_path):

	try:
		auth_file = open(auth_path, 'r')
		field_iterator = 0
		field_auth = {}

		for line in auth_file:
			fields = line.split(" ")
			if field_iterator == 0:
				lenght_field = len(fields)-1
				field_auth['id'] = fields[lenght_field].replace("\n","")
			if field_iterator == 1:
				lenght_field = len(fields)-1
				field_auth['key'] = fields[lenght_field].replace("\n","")
			field_iterator += 1

		return field_auth;

	except Exception as e:
		logging.error("Error: The configuration file could not be opened: '{}'".format(e))


################################################################################################
# The client or application must have permission to read Log Analytics.
# https://dev.loganalytics.io/documentation/1-Tutorials/Direct-API
################################################################################################

def start_log_analytics(first_run):	

	logging.info("Azure Log Analytics starting.")
	url_log_analytics = 'https://api.loganalytics.io/v1'
	current_path = dirname(abspath(__file__))
	path = "{}/last_dates.json".format(current_path)

	try:
		# Getting authentication token
		logging.info("Log Analytics: Getting authentication token.")
		if args.la_auth_path and args.la_tenant_domain:
			auth_fields = read_auth_path(args.la_auth_path)
			log_analytics_token = get_token(auth_fields['id'], auth_fields['key'], 'https://api.loganalytics.io', args.la_tenant_domain)
		elif args.la_id and args.la_key and args.la_tenant_domain:
			log_analytics_token = get_token(args.la_id, args.la_key, 'https://api.loganalytics.io', args.la_tenant_domain)
		else:
			logging.error("Log Analytics: No parameters have been provided for authentication.")

		log_analytics_headers = {
			'Content-Type': 'application/json',
			'Authorization': 'Bearer ' + log_analytics_token
		}

		if first_run == False:
			first_time = "0"
		else:
			first_time = format_date(args.la_time_offset)

		try:
			all_dates = json.load(open(path))
			get_analytic(first_time, all_dates, url_log_analytics, log_analytics_headers)
			with open(os.path.join(path), 'w') as jsonFile:
				json.dump(all_dates, jsonFile)
		except Exception as e:
			logging.error("Error: The file of the last dates could not be uploaded: '{}.".format(e))

	except Exception as e:
		logging.error("Log Analytics: Couldn't get the token for authentication: '{}'.".format(e))	

	logging.info("Azure Log Analytics ending.")

################################################################################################
# Prepares and makes the request, building the query based on the time of event generation.
################################################################################################

def get_analytic(date, last_time_list, url, log_headers):

	analytics_url = "{}/workspaces/{}/query".format(url, args.workspace)	
	logging.info("Log Analytics: Sending a request to the Log Analytics API.")	

	try:
		query_md5 = hashlib.md5(la_format_query).hexdigest()
		# Differentiates the first execution of the script from the rest of the executions.
		if date != "0":
			date_search = date
		else:
			if query_md5 not in last_time_list["log_analytics"]:
				date_search = date
			else:
				date_search = last_time_list["log_analytics"][query_md5]

		logging.info("Log Analytics: The search starts from the date: {} for query: '{}' ".format(date_search, la_format_query))
		query = " {} | order by TimeGenerated asc | where TimeGenerated > datetime({}) ".format(la_format_query, date_search)
		body = {'query': query}
		analytics_request = requests.get(analytics_url, params = body, headers = log_headers)
		get_time_list(analytics_request, last_time_list, date_search, query_md5)
	except Exception as e:
		logging.error("Error: The query requested to the API Log Analytcics has failed. '{}'.".format(e))


################################################################################################
# Obtains the list with the last time generated of each query.
################################################################################################

def get_time_list(request_received, last_timegen, no_results, md5):

	try:
		if request_received.status_code == 200:
			columns = request_received.json()['tables'][0]['columns']
			rows = request_received.json()['tables'][0]['rows']
			time_position = get_TimeGenerated_position(columns)
			# Searches for the position of the TimeGenerated field
			if time_position == -1:
				logging.error("Error: Couldn't get TimeGenerated position")
			else:	
				last_row = len(request_received.json()['tables'][0]['rows']) - 1		
				# Checks for new results
				if last_row < 0:
					logging.info("Log Analytics: There are no new results")
					last_timegen['log_analytics'][md5] = str(no_results)
				else:
					last_timegen['log_analytics'][md5] = request_received.json()['tables'][0]['rows'][last_row][time_position]
					file_json = request_received.json()
					if args.verbose:
						show_content(file_json)
					get_log_analytics_event(columns, rows)
		else:
			if args.verbose == True:
				logging.info("Log Analytics request: {}".format(request_received.status_code))
			request_received.raise_for_status()
	except Exception as e:
		logging.error("Error: It was not possible to obtain the latest event: '{}'.".format(e))


################################################################################################
# Obtains the position of the time field in which the event was generated.
################################################################################################

def get_TimeGenerated_position(columns):

	position=0
	found = "false";
	for column in columns:
		if column['name'] == 'TimeGenerated':
			found = "true"
			break
		position += 1
	if found == "false":
		return -1
	else:
		return position

################################################################################################
# Adds the field name to each row of the result and converts it to json. Writes or sends events
################################################################################################

def get_log_analytics_event(columns, rows):

	columns.append({u'type': u'string', u'name': u'azure_tag'})
	if args.la_tag:
		columns.append({u'type': u'string', u'name': u'log_analytics_tag'})

	for row in rows:
		row.append("azure-log-analytics")
		if args.la_tag:
			row.append(args.la_tag)

	columns_len = len(columns)
	rows_len = len(rows)
	row_iterator = 0
	send_counter = 0

	while row_iterator < rows_len:
		la_result = {}
		column_iterator = 0
		while column_iterator < columns_len:
			la_result[columns[column_iterator]['name']] = rows[row_iterator][column_iterator]
			column_iterator += 1
		row_iterator += 1
		json_result = json.dumps(la_result)
		if send_counter == 15:
			send_counter = 0
			time.sleep(2)
		logging.info("Log Analytics: Sending event by socket.")
		send_socket(json_result)
		send_counter += 1

################################################################################################
# The client or application must have permission to access Microsoft Graph.
# https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-graph-api
################################################################################################

def start_graph():

	logging.info("Azure Graph starting.")
	current_path = dirname(abspath(__file__))
	path = "{}/last_dates.json".format(current_path)
	graph_url_base = 'https://graph.windows.net'

	try:
		# Getting authentication token
		logging.info("Graph: Getting authentication token.")
		if args.graph_auth_path and args.graph_tenant_domain:
			auth_fields = read_auth_path(args.graph_auth_path)
			graph_token = get_token(auth_fields['id'], auth_fields['key'], "", args.graph_tenant_domain)
		elif args.graph_id and args.graph_key and args.graph_tenant_domain:
			graph_token = get_token(args.graph_id, args.graph_key, "", args.graph_tenant_domain)
		else:
			logging.error("Graph: No parameters have been provided for authentication.")

		graph_headers = {
			'Authorization': 'Bearer ' + graph_token
		}
		logging.info("Graph: Getting data.") 

		try:
			all_dates = json.load(open(path))
		except Exception as e:
			logging.error("Error: The file of the last dates could not be updated: '{}.".format(e))

		try:
			graph_md5 = hashlib.md5(graph_format_query).hexdigest()
			# first time for this query
			if graph_md5 not in all_dates['graph']:
				range_time = format_date(args.graph_time_offset)
				date_time = range_time.strftime('%Y-%m-%dT%H:%M:%S.%sZ')
			else:
				date_time = all_dates["graph"][graph_md5]

			logging.info("Graph: The search starts from the date: {} for query: '{}' ".format(date_time, graph_format_query))
			graph_url = "{}/{}/{}&$filter=activityDate%20gt%20{}".format(graph_url_base, args.graph_tenant_domain, graph_format_query, date_time)
			graph_pagination(graph_url, "Graph", graph_headers, graph_md5, all_dates, True)
		except Exception as e:
			logging.error("Error: The request for the query could not be made: '{}'.".format(e))
	except Exception as e:
		logging.error("Error: Couldn't get the token for authentication: '{}'.".format(e))

	logging.info("Graph: End")

################################################################################################
# Pagination of Graph results. TO TEST
################################################################################################

def graph_pagination(url, api, graph_headers, md5, all_dates, first_date):

	pag_request = requests.get(url, headers = graph_headers)
	current_path = dirname(abspath(__file__))
	path = "{}/last_dates.json".format(current_path)

	if pag_request.status_code == 200:
		logging.info("Graph: Request status: {}".format(pag_request.status_code))
		pag_json = pag_request.json()
		pag_json["azure_tag"] = ("azure-ad-graph")
		values_json = pag_json['value']
		send_counter = 0

		if len(values_json) > 0:
			for value in values_json:

				if first_date == True:
					first_date = False
					try:
						all_dates['graph'][md5] = value["activityDate"]
						with open(os.path.join(path), 'w') as jsonFile:
							json.dump(all_dates, jsonFile)
					except Exception as e:
						logging.error("Error: The file of the last dates could not be uploaded: '{}.".format(e))

				value["azure_tag"] = "azure-ad-graph"
				if args.graph_tag:
					value['azure_aad_tag'] = args.graph_tag
				json_result = json.dumps(value)
				if send_counter == 15:
					send_counter = 0
					logging.info("Graph: 15 events sent by socket, time.sleep(2).")
					time.sleep(2)
				logging.info("Graph: Sending event by socket.")
				send_socket(json_result)
				send_counter += 1

		else:
			logging.info("Graph: There are no new results")
		if args.verbose == True:
			show_content(pag_json)
		try: 
			next_url = pag_json['@odata.nextLink']
			graph_pagination(next_url, api, g_headers, md5, all_dates, False)
		except Exception as e:
			logging.info("Graph: No @odata.nextLink field: '{}'.".format(e))
	else:
		logging.info("Graph: Request status: {}".format(pag_request.status_code))
		pag_request.raise_for_status()

################################################################################################
# Get access and content of the storage accounts
# https://docs.microsoft.com/en-us/azure/storage/blobs/storage-quickstart-blobs-python
################################################################################################

def start_storage(first_run):

	logging.info("Azure Storage starting.")

	current_path = dirname(abspath(__file__))
	path = "{}/last_dates.json".format(current_path)

	storage_time = format_date(args.storage_time_offset)
	time_format = str(storage_time)
	length_time_format = len(time_format)-7 
	time_format = time_format[:length_time_format]
	time_format_storage = datetime.datetime.strptime(time_format, '%Y-%m-%d %H:%M:%S')

	try:
		all_dates = json.load(open(path))
	except Exception as e:
		logging.error("Error: The file of the last dates could not be updated: '{}.".format(e))

	try:
		# Authentication
		logging.info("Storage: Authenticating.")
		if args.storage_auth_path:
			auth_fields = read_auth_path(args.storage_auth_path)
			block_blob_service = BlockBlobService(account_name = auth_fields['id'], account_key = auth_fields['key'])
			logging.info("Storage: Authenticated.")
		elif args.account_name and args.account_key:
			block_blob_service = BlockBlobService(account_name = args.account_name, account_key = args.account_key)
			logging.info("Storage: Authenticated.")
		else:
			logging.error("Storage: No parameters have been provided for authentication.")

		logging.info("Storage: Getting containers.")
		# Getting containers from the storage account
		if container_format == '*':
			try:
				containers = block_blob_service.list_containers()
			except Exception as e:
				logging.error("Storage: The containers could not be obtained. '{}'.".format(e))

		# Getting containers from the configuration file
		else:
			try:
				containers = [container_format]
			except Exception as e:
				logging.error("Storage: The containers could not be obtained. '{}'.".format(e))

		# Getting blobs
		get_blobs(containers, block_blob_service, time_format_storage, first_run, all_dates, path)

	except Exception as e:
		logging.error(" Storage account: '{}'.".format(e))

	logging.info("Storage: End")

################################################################################################
# Get the blobs from a container and sends or writes their content
################################################################################################

def get_blobs(containers, block_blob_service, time_format_storage, first_run, all_dates, path):

	for container in containers:

		# Differentiates possible cases of access to containers
		if container_format == '*':
			name = container.name
		else:
			name = container_format

		container_md5 = hashlib.md5(name).hexdigest()
		next_marker = None

		while True:
			try:
				# Extraction of blobs from containers
				logging.info("Storage: Getting blobs.")
				blobs = block_blob_service.list_blobs(name, marker = next_marker)						
			except Exception as e:
				logging.error("Error getting blobs: '{}'.".format(e))	

			if blobs_format == '*':
				search = "."
			else:
				search = blobs_format
				search = search.replace('*','')

			max_blob = utc.localize(time_format_storage)

			for blob in blobs: 
				try:
					# Access to the desired blobs
					if search in blob.name:
						data = block_blob_service.get_blob_to_text(name, blob.name)
						last_modified = blob.properties.last_modified

						if first_run == False:
							if container_md5 not in all_dates["storage"]:
								last_blob = time_format_storage			
							else: 
								blob_date_format = all_dates["storage"][container_md5]
								blob_date_length = len(blob_date_format) - 6
								blob_date_format = blob_date_format[:blob_date_length]
								last_blob = datetime.datetime.strptime(blob_date_format, '%Y-%m-%d %H:%M:%S')
						else:
							last_blob = time_format_storage

						last_blob = utc.localize(last_blob)
						logging.info("Storage: The search starts from the date: {} for blobs in container: '{}' ".format(last_blob, name))

						if last_modified > last_blob:
							if last_modified > max_blob:
								max_blob = last_modified
							if args.verbose == True:
								show_blob(name, blob.name)														
							socket_data = str(data.content)
							socket_data = os.linesep.join([s for s in socket_data.splitlines() if s])
							split_data = socket_data.splitlines()
							storage_counter = 0

							if args.json_file:
								content_list = json.loads(data.content)
								content_records = content_list["records"]
								for log_record in content_records:
									log_record['azure_tag'] = ('azure-storage')
									if args.storage_tag:
										log_record['azure_storage_tag'] = (args.storage_tag)
									if storage_counter == 15:
										storage_counter = 0
										logging.info("Storage: 15 events sent by socket, time.sleep(2).")
										time.sleep(2)
									logging.info("Storage: Sending event by socket.")
									log_json = json.dumps(log_record)
									send_socket(log_json)
									storage_counter += 1
							else:								
								for line in split_data:
									if args.json_inline:   
										size = len(line)
										sub_data = line[1:size]
										if args.storage_tag:
											send_data = '{"azure_tag": "azure-storage",' + '"azure_storage_tag": "' + args.storage_tag + '", ' + sub_data
										else:
											send_data = '{"azure_tag": "azure-storage",' + sub_data
									else:
										if args.storage_tag:
											send_data = "azure_tag: azure-storage. azure_storage_tag: {}. {}".format(args.storage_tag, line)
										else:
											send_data = "azure_tag: azure-storage. {}".format(section, line)

									if send_data != "":
										if storage_counter == 30:
											storage_counter = 0
											logging.info("Storage: 15 events sent by socket, time.sleep(2).")
											time.sleep(2)
										logging.info("Storage: Sending event by socket.")
										send_socket(send_data)
										storage_counter += 1
				except Exception as e:
					logging.error("Storage: sending blob: '{}'.".format(e))

			next_marker = blobs.next_marker
			if not next_marker:
				break

		try:
			if first_run == True:
				write_time = max_blob
			else:
				if container_md5 in all_dates["storage"]:
					previous_time = all_dates["storage"][container_md5]
					previous_time_length = len(previous_time) - 6
					previous_time_format = previous_time[:previous_time_length]
					previous_date = datetime.datetime.strptime(previous_time_format, '%Y-%m-%d %H:%M:%S')
					previous_date = utc.localize(previous_date)
					if previous_date > max_blob:
						write_time = previous_date
					else:
						write_time = max_blob
				else:
					write_time = max_blob 

			all_dates['storage'][container_md5] = str(write_time)
			with open(os.path.join(path), 'w') as jsonFile:
				json.dump(all_dates, jsonFile)
		except Exception as e:
			logging.error("Error: The file of the last dates could not be uploaded: '{}.".format(e))

################################################################################################
# Get the authentication token for calls to both APIs
################################################################################################

def get_token(ID, KEY, resource, domain):
	loggin_url = 'https://login.microsoftonline.com'
	if resource !="":
		body = {
			'client_id': ID,
			'client_secret': KEY,
			'resource': resource,
			'grant_type': 'client_credentials'
		}
	else:
		body ={
			'client_id': ID,
			'client_secret': KEY,
			'grant_type': 'client_credentials'
		}
	auth_url = '{}/{}/oauth2/token?api-version=1.0'.format(loggin_url, domain)
	token_response = requests.post(auth_url, data=body)
	access_token = token_response.json().get('access_token')
	if access_token is None:
		logging.error("Error: Couldn't get access token.")
	else:
		return access_token

################################################################################################
# Sends results by socket
################################################################################################

def send_socket(log):
	
	send_id = 1
	send_location = "Azure"

	sock = socket(AF_UNIX, SOCK_DGRAM)
	sock.connect(ADDR)
	oldbuf = sock.getsockopt(SOL_SOCKET, SO_SNDBUF)

	if oldbuf < BLEN:
		sock.setsockopt(SOL_SOCKET, SO_SNDBUF, BLEN)
		newbuf = sock.getsockopt(SOL_SOCKET, SO_SNDBUF)

	string = "{}:{}:{}".format(send_id, send_location, log)
	string_size = len(string)
	if string_size > 6144:
		logging.info("SOCKET WARNING: The size limit is exceeded, possibly the event will be truncated")

	sock.send(string.encode())


################################################################################################
# Date management.
################################################################################################	

def format_date(conf_date):

	conf_date = conf_date.replace(" ","")
	date_length = len(conf_date)-1
	time_range = int(conf_date[:date_length])
	param_date = conf_date[date_length:]

	if param_date == 'h':
		final_date = datetime.datetime.utcnow() - datetime.timedelta(hours = time_range)
	if param_date == 'm':
		final_date = datetime.datetime.utcnow() - datetime.timedelta(minutes = time_range)
	if param_date == 'd':
		final_date = datetime.datetime.utcnow() - datetime.timedelta(days = time_range)

	return final_date

################################################################################################
# Main function.
################################################################################################

def main():

	set_logger()
	read_arguments()

if __name__ == "__main__":
    main()
