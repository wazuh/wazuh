#!/usr/bin/env python

 ###
 # Integration of Wazuh agent with Kaspersky endpoint security for Linux
 # Copyright (C) 2015-2019, Wazuh Inc.
 #
 # This program is free software; you can redistribute it and/or modify
 # it under the terms of the GNU General Public License as published by
 # the Free Software Foundation; either version 2 of the License, or
 # (at your option) any later version.
 #
 ###

import argparse
import logging
import socket
import os
import sys
import json
from os.path import dirname, abspath
from socket import socket, AF_UNIX, SOCK_DGRAM

##################################################################################################################
# Sets the sockets path
##################################################################################################################

wazuh_path = open('/etc/ossec-init.conf').readline().split('"')[1]
wazuh_queue = '{0}/queue/ossec/queue'.format(wazuh_path)

##################################################################################################################
# Read and parser arguments.
##################################################################################################################			

parser = argparse.ArgumentParser()

parser.add_argument("-v", "--verbose", action='store_true', required = False, help="Debug mode. Example of use: Kaspersky.py -v --boot_scan")
exclusive = parser.add_mutually_exclusive_group()
exclusive.add_argument("--full_scan", action='store_true', required = False, help="Full computer scan. Example of use: Kaspersky.py --full_scan")
exclusive.add_argument("--boot_scan", action='store_true', required = False, help="Boot scan. Example of use: Kaspersky.py --boot_scan")
exclusive.add_argument("--memory_scan", action='store_true', required = False, help="Memory scan. Example of use: Kaspersky.py --memory_scan")
exclusive.add_argument("--custom_scan_folder", metavar = 'folderpath', type = str, required = False, help="Custom scan folder. Example of use: Kaspersky.py --custom_scan_folder '/etc'")
exclusive.add_argument("--custom_scan_file", metavar = 'filepath', type = str, required = False, help="Custom scan file. Example of use: Kaspersky.py --custom_scan_file '/home/centos/sample.txt'")
parser.add_argument("--action", metavar = 'fileaction', type = str, required = False, help="Action to apply to the file after scanning. Only used with --custom_scan_file. Example of use: Kaspersky.py --custom_scan_file '/home/centos/sample.txt' --action Cure ")
exclusive.add_argument("--update_application", action='store_true', required = False, help="Update application. Example of use: Kaspersky.py --update_application")
exclusive.add_argument("--get_task_list", action='store_true', required = False, help="List all the tasks. Example of use: Kaspersky.py --get_task_list")
exclusive.add_argument("--get_task_state", metavar = 'ID', type = str, required = False, help="Get the status of the number of the task entered. Example of use: Kaspersky.py --get_task_state 2, Kaspersky.py --get_task_state Scan_My_Computer")
exclusive.add_argument("--custom_flags", metavar = 'flags', type = str, required = False, help="Run custom flags. Example of use: Kaspersky.py --custom_flags '--get-task-state Scan_My_Computer' ")
exclusive.add_argument("--enable_realtime", action='store_true', required = False, help="Enable Realtime protection. Example of use: Kaspersky.py --enable_realtime")
exclusive.add_argument("--disable_realtime", action='store_true', required = False, help="Disable Realtime protection. Example of use: Kaspersky.py --disable_realtime")



args, unknown = parser.parse_known_args()


##################################################################################################################
# Kaspersky endpoint CLI settings
##################################################################################################################

bin_path = '/opt/kaspersky/kesl/bin'
binary = '/kesl-control'


##################################################################################################################
# Configure the log settings
##################################################################################################################

def set_logger(name, foreground=None):

	if foreground:
		format = '%(asctime)s {}: %(message)s'.format(name)
		logging.basicConfig(level=logging.INFO, format=format, datefmt="%Y-%m-%d %H:%M:%S")


##################################################################################################################
# Kaspersky logs management. 
##################################################################################################################

def logger(msg, mode, foreground=None):

	send_msg(wazuh_queue, msg)

	if foreground:
		if mode == "INFO":
			logging.info(msg)


##################################################################################################################
# Prepares the parameters to be executed by Kaspersky.
##################################################################################################################

def run_kaspersky():

	log_message = "Starting."
	logger(log_message, "INFO", foreground = args.verbose)
	task = ''

	if args.full_scan:
		log_message = "Scan my computer."
		logger(log_message, "INFO", foreground = args.verbose)
		task = '--start-task 2'
	if args.boot_scan:
		log_message = "Boot scan."
		logger(log_message, "INFO", foreground = args.verbose)
		task = '--start-task 4'
	if args.memory_scan:
		log_message = "Memory scan."
		logger(log_message, "INFO", foreground = args.verbose)
		task = '--start-task 5'
	if args.custom_scan_folder:	
		if os.path.exists(args.custom_scan_folder):
			log_message = "Custom scan folder."
			logger(log_message, "INFO", foreground = args.verbose)
			scan_folder(args.custom_scan_folder)
	if args.custom_scan_file:	
		if os.path.exists(args.custom_scan_file):	
			if args.action:
				log_message = "Custom scan file with action."
				logger(log_message, "INFO", foreground = args.verbose)
				task = '--scan-file {} --action {}'.format(args.custom_scan_file, args.action)
			else:
				log_message = "Custom scan file."
				logger(log_message, "INFO", foreground = args.verbose)
				task = '--scan-file {}'.format(args.custom_scan_file)
	if args.update_application:
		log_message = "Update application."
		logger(log_message, "INFO", foreground = args.verbose)
		task = '--update-application'
	if args.get_task_list:
		log_message = "Get task list."
		logger(log_message, "INFO", foreground = args.verbose)
		task = '--get-task-list'
	if args.get_task_state:
		log_message = "Get task state."
		logger(log_message, "INFO", foreground = args.verbose)
		if args.get_task_state > 0:
			task = '--get-task-state {}'.format(args.get_task_state)
	if args.custom_flags:
		log_message = "Run custom flags: {}.".format(args.custom_flags)
		logger(log_message, "INFO", foreground = args.verbose)
		task = '{}'.format(args.custom_flags)
	
	if args.enable_realtime:
		log_message = "Enable realtime."
		logger(log_message, "INFO", foreground=args.verbose)
		task = '--start-task 1'

	if args.disable_realtime:
		log_message = "Disable realtime."
		logger(log_message, "INFO", foreground=args.verbose)
		task = '--stop-task 1'	

	if task != '':
		kesl_control = '{}{} {}'.format(bin_path, binary, task)
		log_message = "{}.".format(kesl_control)
		logger(log_message, "INFO", foreground = args.verbose)
		send_kaspersky(kesl_control)


	log_message = "End."
	logger(log_message, "INFO", foreground = args.verbose)


##################################################################################################################
# Run Kaspersky with the corresponding task. 
##################################################################################################################

def send_kaspersky(task):

	os.system(task)


##################################################################################################################
# Prepares a task to scan a specific directory. 
##################################################################################################################

def scan_folder(folder_path):

	task_name = ' custom_folder_scan_1 '
	task_get = ' --get-settings ' + task_name
	task_set = ' --set-settings ' + task_name
	task_start = ' --start-task ' + task_name
	task_create = ' --create-task {} --type ODS --file '.format(task_name)
	get_query = bin_path + binary + task_get
	set_query = bin_path + binary + task_set
	start_query = bin_path + binary + task_start
	create_query = bin_path + binary + task_create

	log_message = "Custom scan folder: Checking if the custom task exists."
	logger(log_message, "INFO", foreground = args.verbose)
	check_task = os.system(get_query)

	if check_task == 0:
		add_path = '--add-path ' + folder_path
		log_message = "Custom scan folder: Adding the new folder path: {}.".format(folder_path)
		logger(log_message, "INFO", foreground = args.verbose)
		send_kaspersky(set_query + add_path)
		previous_path = get_previous_path(folder_path, get_query)
		if previous_path != '' and previous_path != folder_path:
			delete_path = '--del-path ' + previous_path
			log_message = "Custom scan folder: Deleting the previous path: {}.".format(previous_path)
			logger(log_message, "INFO", foreground = args.verbose)
			send_kaspersky(set_query + delete_path)
	else:
		file_path = create_custom_settings_file(folder_path)
		log_message = "Custom scan folder: Creating the new task from the custom file: {}.".format(file_path)
		logger(log_message, "INFO", foreground = args.verbose)
		send_kaspersky(create_query + file_path)
		remove_custom_settings_file(file_path)

	log_message = "{}.".format(start_query)
	logger(log_message, "INFO", foreground = args.verbose)
	send_kaspersky(start_query)


##################################################################################################################
# Obtains the previous path of an existing task for later deletion. 
##################################################################################################################

def get_previous_path(path, get_query):

	task = get_query
	log_message = "Custom scan folder: Creating the new task from the custom file: {}.".format(path)
	logger(log_message, "INFO", foreground = args.verbose)
	settings = os.popen(task).read()
	settings = settings.split(os.linesep)
	delete_path = ''
	for line in settings:
		if "Path" in line:
			fields = line.split("=")
			delete_path = fields[len(fields)-1]
			if delete_path != path:
				break
	return delete_path


##################################################################################################################
# Creates a custom option file to add the path of the directory to be scanned. 
##################################################################################################################

def create_custom_settings_file(folder_path):

	current_path = dirname(abspath(__file__))
	file_name = "/temporal_configuration_file"
	log_message = "Custom scan folder: Creating the custom file: {}.".format(file_name)
	logger(log_message, "INFO", foreground = args.verbose)
	path = current_path + file_name
	content = '[ScanScope.item_0000]\nAreaDesc=All objects\nUseScanArea=Yes\nPath={}\nAreaMask.item_0000=*'.format(folder_path)
	custom_file = open(path, 'w')
	custom_file.write(content)
	custom_file.close

	return path


##################################################################################################################
# Removes the custom options file after create the task that uses it. 
##################################################################################################################

def remove_custom_settings_file(path):

	log_message = "Custom scan folder: Removing the custom file: {}.".format(path)
	logger(log_message, "INFO", foreground = args.verbose)
	os.remove(path)




##################################################################################################################
# Obtains the status of each task together with its ID.
##################################################################################################################

def parse_tasks_states(tasks):

	ids = []
	states = []
	log_message = "Kaspersky: Getting the status of tasks. "
	logger(log_message, "INFO", foreground = args.verbose)
	tasks = tasks.split(os.linesep)
	for line in tasks:
		if " ID " in line:
			id_fields = line.split(":")
			ids.append(id_fields[len(id_fields)-1].replace(" ",""))
		if " State " in line:
			states_fields = line.split(":")
			states.append(states_fields[len(states_fields)-1].replace(" ",""))	

	states_dict = dict(zip(ids, states))
	return states_dict


##################################################################################################################
# Send logs events by socket. 
##################################################################################################################

def send_msg(wazuh_queue, msg):

	send_id = 1
	send_location = "kaspersky-integration"
	formatted = {}
	formatted['integration'] = 'kaspersky'
	formatted['message'] = msg
	json.dumps(formatted, indent=4)
	content = '{}:{}:{}'.format(send_id, send_location, json.dumps(formatted))
	s = socket(AF_UNIX, SOCK_DGRAM)
	try:
		s.connect(wazuh_queue)
	except:
		print('Error: Wazuh must be running.')
		sys.exit(1)
	s.send(content.encode())
	s.close()


##################################################################################################################
# Main function
##################################################################################################################

def main():
	set_logger('wazuh-kaspersky', foreground=args.verbose)
	run_kaspersky()


if __name__ == "__main__":
	main()
