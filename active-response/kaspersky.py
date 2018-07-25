#!/usr/bin/env python

 ###
 # Integration of Wazuh agent with Kaspersky endpoint security for Linux
 # Copyright (C) 2018 Wazuh, Inc.
 #
 # This program is free software; you can redistribute it and/or modify
 # it under the terms of the GNU General Public License as published by
 # the Free Software Foundation; either version 2 of the License, or
 # (at your option) any later version.
 #
 ###

##################################################################################################################
# Kaspersky Integration 
# yum install https://products.s.kaspersky-labs.com/multilanguage/endpoints/keslinux10/kesl-10.1.0-5960.x86_64.rpm
##################################################################################################################

import argparse
import logging
import socket
import os
import sys
from os.path import dirname, abspath

##################################################################################################################
# Parser custom flags. Adapts the input of the argument --custom_flags to be used by argparser. 
##################################################################################################################

def parser_custom_flags(arr):

	my_list = []
	verbose = "false"
	sections = arr.split(" ")
	custom_field = arr.replace("--custom_flags ","")

	if "-v" in arr:
		verbose = "true"
		if sections[0] == "-v": 			
			custom_field = custom_field.replace("-v ","")
		else:
			custom_field = custom_field.replace(" -v","")

	my_list.append("--custom_flags")
	my_list.append(custom_field)
	if verbose == "true":
		my_list.append("-v")
	return my_list


##################################################################################################################
# Read and parser arguments.
##################################################################################################################			

arr = sys.argv[8]

if "--custom_flags" in arr:
	arr = parser_custom_flags(arr)
else:
	arr = arr.split(" ")

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

args = parser.parse_args(arr)


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
		hostname = socket.gethostname()
		format = '%(asctime)s {0} {1}: %(message)s'.format(hostname, name)
		logging.basicConfig(level=logging.INFO, format=format, datefmt="%Y-%m-%d %H:%M:%S")


##################################################################################################################
# Prepares the parameters to be executed by Kaspersky.
##################################################################################################################

def run_kaspersky():

	logging.info("Kaspersky: Starting.")
	task = ''

	if args.full_scan:
		check_tasks_status()
		logging.info("Kaspersky: Scan my computer.")
		task = '--start-task 2'
	if args.boot_scan:
		check_tasks_status()
		logging.info("Kaspersky: Boot scan.")
		task = '--start-task 4'
	if args.memory_scan:
		check_tasks_status()
		logging.info("Kaspersky: Memory scan.")
		task = '--start-task 5'
	if args.custom_scan_folder:	
		check_tasks_status()
		if os.path.exists(args.custom_scan_folder):
			logging.info("Kaspersky: Custom scan folder.")
			scan_folder(args.custom_scan_folder)
	if args.custom_scan_file:
		check_tasks_status()	
		if os.path.exists(args.custom_scan_file):	
			if args.action:
				logging.info("Kaspersky: Custom scan file with action.")
				task = '--scan-file {} --action {}'.format(args.custom_scan_file, args.action)
			else:
				logging.info("Kaspersky: Custom scan file.")
				task = '--scan-file {}'.format(args.custom_scan_file)
	if args.update_application:
		check_tasks_status()
		logging.info("Kaspersky: Update application.")
		task = '--update-application'
	if args.get_task_list:
		logging.info("Kaspersky: Get task list.")
		task = '--get-task-list'
	if args.get_task_state:
		logging.info("Kaspersky: Get task state.")
		if args.get_task_state > 0:
			task = '--get-task-state {}'.format(args.get_task_state)
	if args.custom_flags:
		check_tasks_status()
		logging.info("Kaspersky: Run custom flags: {}.".format(args.custom_flags))
		task = '{}'.format(args.custom_flags)
	
	if task != '':
		kesl_control = '{}{} {}'.format(bin_path, binary, task)
		logging.info("Kaspersky: {}.".format(kesl_control))
		send_kaspersky(kesl_control)

	logging.info("Kaspersky: End.")


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

	logging.info("Kaspersky: Custom scan folder: Checking if the custom task exists.")
	check_task = os.system(get_query)

	if check_task == 0:
		add_path = '--add-path ' + folder_path
		logging.info("Kaspersky: Custom scan folder: Adding the new folder path: {}.".format(folder_path))
		send_kaspersky(set_query + add_path)
		previous_path = get_previous_path(folder_path, get_query)
		if previous_path != '' and previous_path != folder_path:
			delete_path = '--del-path ' + previous_path
			logging.info("Kaspersky: Custom scan folder: Deleting the previous path: {}.".format(previous_path))
			send_kaspersky(set_query + delete_path)
	else:
		file_path = create_custom_settings_file(folder_path)
		logging.info("Kaspersky: Custom scan folder: Creating the new task from the custom file: {}.".format(file_path))
		send_kaspersky(create_query + file_path)
		remove_custom_settings_file(file_path)

	logging.info("Kaspersky: {}.".format(start_query))
	send_kaspersky(start_query)


##################################################################################################################
# Obtains the previous path of an existing task for later deletion. 
##################################################################################################################

def get_previous_path(path, get_query):

	task = get_query
	logging.info("Kaspersky: Custom scan folder: Creating the new task from the custom file: {}.".format(path))
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
	logging.info("Kaspersky: Custom scan folder: Creating the custom file: {}.".format(file_name))
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

	logging.info("Kaspersky: Custom scan folder: Removing the custom file: {}.".format(path))
	os.remove(path)

##################################################################################################################
# Check if there are any tasks in execution (ignoring the ones that are always in execution).
# If there is a task in progress, abort the run. 
##################################################################################################################

def check_tasks_status():

	logging.info("Kaspersky: Checking the status of tasks. ")
	task = '--get-task-list'
	ignore_list = ["1","9","10","12"]
	all_tasks = '{}{} {}'.format(bin_path, binary, task)
	tasks_info = os.popen(all_tasks).read()
	tasks_states_dict = parse_tasks_states(tasks_info)
	keylist = tasks_states_dict.keys()
	for key in keylist:
		if key not in ignore_list:
			if tasks_states_dict[key] !="Stopped":
				logging.info("Kaspersky: There is at least one task in progress. Task ID:{} Status:{}. Exit.".format(key,tasks_states_dict[key]))
				sys.exit(1)
				print(key, tasks_states_dict[key])


##################################################################################################################
# Obtains the status of each task together with its ID.
##################################################################################################################

def parse_tasks_states(tasks):

	ids = []
	states = []
	logging.info("Kaspersky: Getting the status of tasks. ")
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
# Main function
##################################################################################################################

def main():

	set_logger('wazuh-kaspersky', foreground=args.verbose)
	run_kaspersky()


if __name__ == "__main__":
	main()
