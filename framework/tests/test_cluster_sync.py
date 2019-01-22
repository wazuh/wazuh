#!/usr/bin/env python

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import argparse
import sys
import os
import shutil
from os import path, chmod
from stat import S_IRWXG, S_IRWXU

class WazuhHelpFormatter(argparse.ArgumentParser):
         
    def format_help(self):
        msg = """The test creates missing, extra and shared files to verify that all items in the cluster are synchronizing correctly.

usage: test_cluster_sync.py [-h] [--clear [CLEAR] | -w [WORKER] | -m [MASTER] | -c CHECK] [-a N_AGENTS] [-p OSSEC_PATH]

Master
    -m: Test the master node.
    -p '/var/ossec': Set ossec path (by default '/var/ossec').
    -c 'master': Check if the worker node has synchronized correctly with the master after a test.
    --clean: Recover the initial directory structure.

    Flow:
        - Run 'python test_cluster_sync.py -m' on the master node.
        - Execute 'python test_cluster_sync.py -c 'master' in a worker node to check the result of synchronization with the master node. If nothing has failed everything should have an 'OK', otherwise an 'X'.
        - To recover the initial structure: 'python test_cluster_sync.py --clean'


Worker
    -w: Test worker node.
    -p '/var/ossec': Set ossec path (by default '/var/ossec').
    -a n: Create n agents-info (by default 5).
    -c 'worker': Check if the worker node has synchronized correctly with the master after a test.
    --clean: Recover the initial directory structure.

    Flow:
        - Run 'python test_cluster_sync.py -w' on a worker node.
        - Execute 'python test_cluster_sync.py -c 'worker' in a worker node to check the result of the synchronization (note: agents-info will not be checked). If nothing has failed everything should have an 'OK', otherwise an 'X'.
        - To recover the initial structure: 'python test_cluster_sync.py --clean'
"""
        return msg
        
    def error(self, message):
        print("Wrong arguments: {0}".format(message))
        self.print_help()
        exit(1)

parser=WazuhHelpFormatter(usage='custom usage')       
exclusive = parser.add_mutually_exclusive_group()
exclusive.add_argument('--clean', type=bool, dest='clean', help='clean missing and extra files', required=False, nargs='?',const=True, default=False )
exclusive.add_argument('-w', '--worker', type=bool, dest='worker', help='Test worker node', required=False, nargs='?',const=True, default=False)
exclusive.add_argument('-m', '--master', type=bool, dest='master', help='Test master node', required=False, nargs='?',const=True, default=False)
exclusive.add_argument('-c', '--check', type=str, dest='check', help='Check in worker missing and extra files (for worker test or master test)', required=False)

parser.add_argument('-a', '--agents', type=int, dest='n_agents', help='Create n agents-info', required=False)
parser.add_argument('-p', '--path', type=str, dest='ossec_path', help='Set ossec path', required=False)

args = parser.parse_args()


def updt(total, progress):
    barLength, status = 20, ""
    progress = float(progress) / float(total)
    if progress >= 1.:
        progress, status = 1, "\r\n"
    block = int(round(barLength * progress))
    text = "\r   [{}] {:.0f}% {}".format(
        "#" * block + "-" * (barLength - block), round(progress * 100, 0),
        status)
    sys.stdout.write(text)
    sys.stdout.flush()

agent_id = 999

def worker(ossec_path="/var/ossec", n_agents=5):
    print ("Executing test for WORKER node...")

    ###
    print ('/etc/')
    with open("{}/etc/client.keys".format(ossec_path), 'a') as ck:
        ck.write("\n{} test any aad3f2f3dc3ec3b2ffc76ecd0e74fbb8657bb09253abd0c9c06b1908328ae370".format(agent_id))
    print (" - Modified 'client.keys' (shared).")
    ###


    ###
    print ('/etc/shared/')
    directory = "{}/etc/shared/tests".format(ossec_path)
    if not os.path.exists(directory):
        os.makedirs(directory)
        chmod(path.dirname(directory), S_IRWXU | S_IRWXG)
        print (" - Created directory '{}' (extra).".format(directory))
    else:
        print (" - Directory '{}' (extra).".format(directory))

    file = "{}/merged.mg".format(directory)
    if not os.path.exists(file):
        with open("{}".format(file), 'w') as ck:
            ck.write("Text asdfghjklqwertyuiop\n")
        chmod(path.dirname(file), S_IRWXU | S_IRWXG)
        print (" - Created file '{}' (extra).".format(file))
    else:
        print (" - File '{}' (extra).".format(file))
    ###


    ###
    print ('/etc/rules/')
    directory = "{}/etc/rules/test_rules".format(ossec_path)
    if not os.path.exists(directory):
        os.makedirs(directory)
        chmod(path.dirname(directory), S_IRWXU | S_IRWXG)
        print (" - Created directory '{}' (extra).".format(directory))
    else:
        print (" - Directory '{}' (extra).".format(directory))

    file = "{}/test_rule".format(directory)
    if not os.path.exists(file):
        with open("{}".format(file), 'w') as ck:
            ck.write("#Text asdfghjklqwertyuiop\n")
        chmod(path.dirname(file), S_IRWXU | S_IRWXG)
        print (" - Created file '{}' (extra).".format(file))
    else:
        print (" - File '{}' (extra).".format(file))

    file2 = "{}/etc/rules/local_rules.xml".format(ossec_path)
    if os.path.exists(file2):
        os.remove("{}".format(file2))
        print (" - Removed file '{}' (missing).".format(file2))
    else:
        print (" - File '{}' doesn't exist (missing).".format(file2))
    print ("   (*) Note: There are only one rule and one decoder, the rule is deleted and the decoder is modified.")
    ###


    ###
    print ('/etc/decoders/')
    directory = "{}/etc/decoders/test_decoders".format(ossec_path)
    if not os.path.exists(directory):
        os.makedirs(directory)
        chmod(path.dirname(directory), S_IRWXU | S_IRWXG)
        print (" - Created directory '{}' (extra).".format(directory))
    else:
        print (" - Directory '{}' (extra).".format(directory))

    file = "{}/test_decoder".format(directory)
    if not os.path.exists(file):
        with open("{}".format(file), 'w') as ck:
            ck.write("#Text asdfghjklqwertyuiop\n")
        chmod(path.dirname(file), S_IRWXU | S_IRWXG)
        print (" - Created file '{}' (extra).".format(file))
    else:
        print (" - File '{}' (extra).".format(file))

    file3 = "{}/etc/decoders/local_decoder.xml".format(ossec_path)
    with open("{}".format(file3), 'a') as ck:
        ck.write("\n# Modified\n")
    chmod(path.dirname(file3), S_IRWXU | S_IRWXG)
    print (" - Modified file '{}' (shared).".format(file3))
    ###


    ###
    print ('/etc/lists/')
    directory = "{}/etc/lists/tests_lists".format(ossec_path)
    if not os.path.exists(directory):
        os.makedirs(directory)
        chmod(path.dirname(directory), S_IRWXU | S_IRWXG)
        print (" - Created directory '{}' (extra).".format(directory))
    else:
        print (" - Directory '{}' (extra).".format(directory))

    file = "{}/test_file".format(directory)
    if not os.path.exists(file):
        with open("{}".format(file), 'w') as ck:
            ck.write("Text asdfghjklqwertyuiop\n")
        chmod(path.dirname(file), S_IRWXU | S_IRWXG)
        print (" - Created file '{}' (extra).".format(file))
    else:
        print (" - File '{}' (extra).".format(file))

    directory2 = "{}/etc/lists/amazon/".format(ossec_path)
    if os.path.exists(directory2):
        shutil.rmtree("{}".format(directory2))
        print (" - Removed directory '{}' and his content (missing).".format(directory2))
    else:
        print (" - Directory '{}' doesn't exist (missing).".format(directory2))
    ###


    ###
    test_agent_info = 'Linux |{} |4.9.38-16.35.amzn1.x86_64 |#1 SMP Sat Apr 5 01:39:35 UTC 2017 |x86_64 [Amazon Linux AMI|amzn: 2017.09] - Wazuh v3.3.2 / 247926f11184f0be0631e0658344aaeb\n\
    008b8ac1cf33c4b6df2d991249a5bbff merged.mg\n\
    \n\
    \n\
    #"manager_hostname":manager\n\
    #"node_name":{}'

    node_name = "node0{}".format(2)
    start = 0
    print ("Creating {} agents-info.".format(n_agents - start))
    for i in range(start, n_agents):
        agent_name = "agent{}".format(i)
        with open("{}/queue/agent-info/{}-any".format(ossec_path, agent_name), 'w') as f:
            f.write(test_agent_info.format(agent_name,node_name))
        updt(n_agents, i - start + 1)
    ###


def master(ossec_path="/var/ossec"):
    print ("Executing test for MASTER node...")

    ###
    print ('/etc/')
    with open("{}/etc/client.keys".format(ossec_path), 'a') as ck:
        ck.write("\n{} test any aad3f2f3dc3ec3b2ffc76ecd0e74fbb8657bb09253abd0c9c06b1908328ae370".format(agent_id))
    print (" - Modified 'client.keys' (shared).")
    ###


    ###
    print ('/etc/shared/')
    directory = "{}/etc/shared/tests".format(ossec_path)
    if not os.path.exists(directory):
        os.makedirs(directory)
        chmod(path.dirname(directory), S_IRWXU | S_IRWXG)
        print (" - Created directory '{}' (missing).".format(directory))
    else:
        print (" - Directory '{}' (missing).".format(directory))

    file = "{}/merged.mg".format(directory)
    if not os.path.exists(file):
        with open("{}".format(file), 'w') as ck:
            ck.write("Text asdfghjklqwertyuiop\n")
        chmod(path.dirname(file), S_IRWXU | S_IRWXG)
        print (" - Created file '{}' (missing).".format(file))
    else:
        print (" - File '{}' (missing).".format(file))
    ###


    ###
    print ('/etc/rules/')
    directory = "{}/etc/rules/test_rules".format(ossec_path)
    if not os.path.exists(directory):
        os.makedirs(directory)
        chmod(path.dirname(directory), S_IRWXU | S_IRWXG)
        print (" - Created directory '{}' (missing).".format(directory))
    else:
        print (" - Directory '{}' (missing).".format(directory))

    file = "{}/test_rule".format(directory)
    if not os.path.exists(file):
        with open("{}".format(file), 'w') as ck:
            ck.write("#Text asdfghjklqwertyuiop\n")
        chmod(path.dirname(file), S_IRWXU | S_IRWXG)
        print (" - Created file '{}' (missing).".format(file))
    else:
        print (" - File '{}' (missing).".format(file))

    file2 = "{}/etc/rules/local_rules.xml".format(ossec_path)
    if os.path.exists(file2):
        os.remove("{}".format(file2))
        print (" - Removed file '{}' (extra).".format(file2))
    else:
        print (" - File '{}' doesn't exist (extra).".format(file2))
    print ("   (*) Note: There are only one rule and one decoder, the rule is deleted and the decoder is modified.")
    ###


    ###
    print ('/etc/decoders/')
    directory = "{}/etc/decoders/test_decoders".format(ossec_path)
    if not os.path.exists(directory):
        os.makedirs(directory)
        chmod(path.dirname(directory), S_IRWXU | S_IRWXG)
        print (" - Created directory '{}' (missing).".format(directory))
    else:
        print (" - Directory '{}' (missing).".format(directory))

    file = "{}/test_decoder".format(directory)
    if not os.path.exists(file):
        with open("{}".format(file), 'w') as ck:
            ck.write("#Text asdfghjklqwertyuiop\n")
        chmod(path.dirname(file), S_IRWXU | S_IRWXG)
        print (" - Created file '{}' (missing).".format(file))
    else:
        print (" - File '{}' (missing).".format(file))

    file3 = "{}/etc/decoders/local_decoder.xml".format(ossec_path)
    with open("{}".format(file3), 'a') as ck:
        ck.write("\n# Modified\n")
    print (" - Modified file '{}' (shared).".format(file3))
    ###


    ###
    print ('/etc/lists/')
    directory = "{}/etc/lists/tests_lists".format(ossec_path)
    if not os.path.exists(directory):
        os.makedirs(directory)
        chmod(path.dirname(directory), S_IRWXU | S_IRWXG)
        print (" - Created directory '{}' (missing).".format(directory))
    else:
        print (" - Directory '{}' (missing).".format(directory))

    file = "{}/test_file".format(directory)
    if not os.path.exists(file):
        with open("{}".format(file), 'w') as ck:
            ck.write("Text asdfghjklqwertyuiop\n")
        chmod(path.dirname(file), S_IRWXU | S_IRWXG)
        print (" - Created file '{}' (missing).".format(file))
    else:
        print (" - File '{}' (missing).".format(file))

    directory2 = "{}/etc/lists/amazon/".format(ossec_path)
    if os.path.exists(directory2):
        shutil.rmtree("{}".format(directory2))
        print (" - Removed directory '{}' and his content (extra).".format(directory2))
    else:
        print (" - Directory '{}' doesn't exist (extra).".format(directory2))
    ###


def check_worker_test_worker(ossec_path="/var/ossec"):
    print ('Checking missing and shared files...')
    ###
    print ('/etc/shared/')
    directory = "{}/etc/shared/tests".format(ossec_path)
    if os.path.exists(directory):
        print (" - Directory '{}' exists (X).".format(directory))
    else:
        print (" - Directory '{}' doesn't exist (OK).".format(directory))

    file = "{}/merged.mg".format(directory)
    if os.path.exists(file):
        pass
        #print (" - File '{}' exists (X) (*ToDo*).".format(file))
    else:
        print (" - File '{}' doesn't exist (OK).".format(file))
    ###


    ###
    print ('/etc/rules/')
    directory = "{}/etc/rules/test_rules".format(ossec_path)
    if os.path.exists(directory):
        pass
        #print (" - Directory '{}' exists (X) (*ToDo*).".format(directory))
    else:
        print (" - Directory '{}' doesn't exist (OK).".format(directory))

    file = "{}/test_rule".format(directory)
    if os.path.exists(file):
        print (" - File '{}' exists (X).".format(file))
    else:
        print (" - File '{}' doesn't exist (OK).".format(file))

    file2 = "{}/etc/rules/local_rules.xml".format(ossec_path)
    if os.path.exists(file2):
        print (" - File '{}'  exists (OK).".format(file2))
    else:
        print (" - File '{}' doesn't exist (X).".format(file2))
    ###


    ###
    print ('/etc/decoders/')
    directory = "{}/etc/decoders/test_decoders".format(ossec_path)
    if os.path.exists(directory):
        pass
        #print (" - Directory '{}' exists (X) (*ToDo*).".format(directory))
    else:
        print (" - Directory '{}' doesn't exist (OK).".format(directory))

    file = "{}/test_decoder".format(directory)
    if os.path.exists(file):
        print (" - File '{}' exists (X).".format(file))
    else:
        print (" - File '{}' doesn't exist (OK).".format(file))
    ###


    ###
    print ('/etc/lists/')
    directory = "{}/etc/lists/tests_lists".format(ossec_path)
    if os.path.exists(directory):
        pass
        #print (" - Directory '{}' exists (X) (*ToDo*).".format(directory))
    else:
        print (" - Directory '{}' doesn't exist (OK).".format(directory))

    file = "{}/test_file".format(directory)
    if os.path.exists(file):
        print (" - File '{}' exists (X).".format(file))
    else:
        print (" - File '{}' doesn't exist (OK).".format(file))

    directory2 = "{}/etc/lists/amazon/".format(ossec_path)
    if os.path.exists(directory2):
        print (" - Directory '{}' exists (OK).".format(directory2))
    else:
        print (" - Directory '{}' doesn't exist (X).".format(directory2))
    ###


def check_worker_test_master(ossec_path="/var/ossec"):
    print ('Checking missing and shared files...')
    ###
    print ('/etc/shared/')
    directory = "{}/etc/shared/tests".format(ossec_path)
    if os.path.exists(directory):
        print (" - Directory '{}' exists (OK).".format(directory))
    else:
        print (" - Directory '{}' doesn't exist (X).".format(directory))

    file = "{}/merged.mg".format(directory)
    if os.path.exists(file):
        print (" - File '{}' exists (OK).".format(file))
    else:
        print (" - File '{}' doesn't exist (X).".format(file))
    ###


    ###
    print ('/etc/rules/')
    directory = "{}/etc/rules/test_rules".format(ossec_path)
    if os.path.exists(directory):
        print (" - Directory '{}' exists (OK).".format(directory))
    else:
        print (" - Directory '{}' doesn't exist (X).".format(directory))

    file = "{}/test_rule".format(directory)
    if os.path.exists(file):
        print (" - File '{}' exists (OK).".format(file))
    else:
        print (" - File '{}' doesn't exist (X).".format(file))

    file2 = "{}/etc/rules/local_rules.xml".format(ossec_path)
    if os.path.exists(file2):
        print (" - File '{}'  exists (X).".format(file2))
    else:
        print (" - File '{}' doesn't exist (OK).".format(file2))
    ###


    ###
    print ('/etc/decoders/')
    directory = "{}/etc/decoders/test_decoders".format(ossec_path)
    if os.path.exists(directory):
        print (" - Directory '{}' exists (OK).".format(directory))
    else:
        print (" - Directory '{}' doesn't exist (X).".format(directory))

    file = "{}/test_decoder".format(directory)
    if os.path.exists(file):
        print (" - File '{}' exists (OK).".format(file))
    else:
        print (" - File '{}' doesn't exist (X).".format(file))
    ###


    ###
    print ('/etc/lists/')
    directory = "{}/etc/lists/tests_lists".format(ossec_path)
    if os.path.exists(directory):
        print (" - Directory '{}' exists (OK).".format(directory))
    else:
        print (" - Directory '{}' doesn't exist (X).".format(directory))

    file = "{}/test_file".format(directory)
    if os.path.exists(file):
        print (" - File '{}' exists (OK).".format(file))
    else:
        print (" - File '{}' doesn't exist (X).".format(file))

    directory2 = "{}/etc/lists/amazon/".format(ossec_path)
    if os.path.exists(directory2):
        pass
        #print (" - Directory '{}' exists (X) (*ToDo*).".format(directory2))
    else:
        print (" - Directory '{}' doesn't exist (OK).".format(directory2))
    ###


def clean(ossec_path="/var/ossec"):
    print ('Reset client.keys, and missing and shared files...')

    ###
    new_content = []
    with open("{}/etc/client.keys".format(ossec_path), 'a+') as ck:
        lines = ck.readlines()
        for line in lines:
            if not str(agent_id) + " " in line:
                new_content.append(line)
    with open("{}/etc/client.keys".format(ossec_path), 'w') as ck:
        ck.writelines(new_content)
    ###

    ###
    directory = "{}/etc/shared/tests".format(ossec_path)
    file = "{}/merged.mg".format(directory)
    if os.path.exists(file):
        os.remove("{}".format(file))
    if os.path.exists(directory):
        shutil.rmtree("{}".format(directory))
    ###


    ###
    directory = "{}/etc/rules/test_rules".format(ossec_path)
    file = "{}/test_rule".format(directory)
    if os.path.exists(file):
        os.remove("{}".format(file))
    if os.path.exists(directory):
        shutil.rmtree("{}".format(directory))

    file2 = "{}/etc/rules/local_rules.xml".format(ossec_path)
    if not os.path.exists(file2):
        with open("{}".format(file2), 'w') as ck:
            ck.write("#Text\n")
        chmod(path.dirname(file2), S_IRWXU | S_IRWXG)
    ###


    ###
    directory = "{}/etc/decoders/test_decoders".format(ossec_path)
    file = "{}/test_decoder".format(directory)
    if os.path.exists(file):
        os.remove("{}".format(file))
    if os.path.exists(directory):
        shutil.rmtree("{}".format(directory))
    ###


    ###
    directory = "{}/etc/lists/tests_lists".format(ossec_path)
    file = "{}/test_file".format(directory)
    if os.path.exists(file):
        os.remove("{}".format(file))
    if os.path.exists(directory):
        shutil.rmtree("{}".format(directory))

    directory2 = "{}/etc/lists/amazon".format(ossec_path)
    if not os.path.exists(directory2):
        os.makedirs(directory2)
    chmod(path.dirname(directory2), S_IRWXU | S_IRWXG)

    list_files = []
    list_files.append("{}/aws-eventnames".format(directory2))
    list_files.append("{}/aws-eventnames.cdb".format(directory2))
    for file in list_files:
        if not os.path.exists(file):
            with open("{}".format(file), 'w') as ck:
                ck.write("#Text\n")
    ###
    print ('Done.')


if __name__ == "__main__":
    args = parser.parse_args()
    if args.worker:
        n_agents = args.n_agents if args.n_agents else 5
        ossec_path = args.ossec_path if args.ossec_path else "/var/ossec"
        worker(ossec_path=ossec_path, n_agents=n_agents)

    elif args.master:
        ossec_path = args.ossec_path if args.ossec_path else "/var/ossec"
        master(ossec_path=ossec_path)

    elif args.check:
        if args.check == "master":
            check_worker_test_master()
        elif args.check == "worker":
            check_worker_test_worker()
        else:
            print ("Expected argument: master or worker")

    elif args.clean:
        clean()
    else:
        parser.print_help()
        exit()


