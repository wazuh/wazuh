#!/usr/bin/env python

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
from os import path
import asyncore
import threading
import time
import logging

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s: %(message)s')

try:
    sys.path.append(path.dirname(sys.argv[0]) + '/../framework')

    from wazuh import Wazuh
    from wazuh import common
    from wazuh.cluster import cluster
    from wazuh.cluster.master import MasterManager, MasterInternalSocketHandler
    from wazuh.cluster.worker import WorkerManager
    from wazuh.cluster.communication import InternalSocketThread
except Exception as e:
    print("Error importing 'Wazuh' package: {0}".format(e))
    sys.exit(1)

#
# Tests
#
def test_multiple_requests_from_worker(thread, name, my_worker, n):
    ok_requests = 0

    start = time.time()
    for i in range(n):
        response = my_worker.send_request('echo-c', 'Keep-alive from worker!')
        processed_response = my_worker.process_response(response)
        if processed_response:
            ok_requests += 1
            print(processed_response)
        else:
            print("No response")
    end = time.time()

    print("\n#Results '{0}' - test_multiple_requests_from_worker:".format(name))
    print("Total requests: {}".format(n))
    print("\tOK: {0}".format(ok_requests))
    print("\tKO: {0}".format(n-ok_requests))
    print("\tTime: {0}".format(end - start))
    print("")

    thread.stop()

def test_multiple_requests_from_master(thread, name, server, n):
    ok_requests = 0

    start = time.time()
    for i in range(n):
        # Broadcast
        for worker_name, response in server.send_request_broadcast('echo-m', 'Keep-alive from server!'):
            processed_response = server.handler.process_response(response)
            if processed_response:
                ok_requests += 1
                print(processed_response)
            else:
                print("No response")
    end = time.time()

    print("\n#Results '{0}' - test_multiple_requests_from_master:".format(name))
    print("Total requests: {}".format(n))
    print("\tOK: {0}".format(ok_requests))
    print("\tKO: {0}".format(n-ok_requests))
    print("\tTime: {0}".format(end - start))
    print("")

    thread.stop()


def test_send_file(thread, my_worker, file_path):
    before = time.time()
    print("Sending file: {}".format(file_path))
    response = my_worker.send_file('sync_c_m', file_path)
    print("Response: {}".format(response))
    after = time.time()
    print("Total time: {}".format(after - before))
    thread.stop()


def test_cluster_worker_requests(thread, my_worker):
    requests_list = [
    ]

    for req, data, expected_res in requests_list:
        print("Testing request {}".format(req))
        local_res = my_worker.process_response(my_worker.send_request(command = req, data = data))
        if expected_res != local_res:
            print("Request {} failed. Expected response: '{}', response: '{}'".format(req, expected_res, local_res))
        else:
            print("Request {} successfully completed".format(req))

    thread.stop()


def test_cluster_master_requests(thread, my_master):
    requests_list = [
        ("req_sync_m_c", None, "Confirmation received: Starting sync from master"),
        ("getintegrity", None, {'/etc/client.keys':'pending'})
    ]

    time.sleep(2) # wait for workers to connect
    for req, data, expected_res in requests_list:
        print("Testing request {}".format(req))
        for c_name, res in my_master.send_request_broadcast(command=req, data=data):
            print("Worker {}".format(c_name))
            local_res = my_master.handler.process_response(res)
            if expected_res != local_res:
                print("Request {} failed. Expected response: '{}', response: '{}'".format(req, expected_res, local_res))
            else:
                print("Request {} successfully completed".format(req))

    thread.stop()


#
# Master threads
#
class MasterTest(threading.Thread):

    def __init__(self, t_name, server, test_name, test_size=0):
        threading.Thread.__init__(self)
        self.daemon = True
        self.running = True
        self.server = server
        self.name = t_name
        self.test = test_name
        self.test_size = test_size


    def run(self):

        while self.running:
            if self.test == 'test1':
                if len(self.server.get_connected_workers()) > 0:
                    test_multiple_requests_from_master(self, self.name, self.server, self.test_size)
                else:
                    print("Waiting for workers")
                    time.sleep(2)
            elif self.test == 'testm':
                test_cluster_master_requests(self, self.server)
            else:
                print("T: No test selected")


    def stop(self):
        self.running = False

#
# Worker threads
#
class WorkerTest(threading.Thread):

    def __init__(self, t_name, test_name, test_size=0, filepath=""):
        threading.Thread.__init__(self)
        self.daemon = True
        self.worker = None
        self.running = True
        self.name = t_name
        self.test = test_name
        self.test_size = test_size
        self.filepath = filepath


    def run(self):
        while self.running:
            if self.worker and self.worker.is_connected():

                if self.test == 'test1':
                    test_multiple_requests_from_worker(self, self.name, self.worker, n=self.test_size)
                elif self.test == 'testf':
                    test_send_file(self, self.worker, filepath)
                elif self.test == 'testc':
                    test_cluster_worker_requests(self, self.worker)
                else:
                    print("T: No test selected")

                #self.worker.handle_close()
                # self.stop()

    def setworker(self, worker):
        self.worker = worker


    def stop(self):
        self.running = False

#
# Master main
#
def master_main(test_name, test_size):
    # Read config
    c_config = cluster.read_config()

    # Initiate master
    master = MasterManager(c_config)

    internal_socket_thread = InternalSocketThread("c-internal")
    internal_socket_thread.start()
    internal_socket_thread.setmanager(master, MasterInternalSocketHandler)

    # Test threads
    if test_name == "test0": # just connect
        print("Test: just listening")
        asyncore.loop(timeout=1, map=master.map)
    elif test_name == 'test1':
        m_test_thread = MasterTest('thread 0', master, test_name, test_size)
        m_test_thread.start()

        # Loop
        asyncore.loop(timeout=1, map=master.map)
        print("loop end")
    elif test_name == 'test2':

        thread_pool = []
        for i in range(10):
            thread_pool.append(MasterTest('thread {0}'.format(i), master, 'test1', test_size))

        for i in range(10):
            thread_pool[i].start()

        asyncore.loop(timeout=1, map=master.map)
    elif test_name == 'testm':
        m_test_thread = MasterTest('thread0', master, test_name)
        m_test_thread.start()
        asyncore.loop(timeout=1, map=master.map)
    else:
        print("No test selected")



    print("Exiting...")

#
# Worker main
#
def worker_main(test_name, test_size, filepath):
    c_config = cluster.read_config()


    # Test threads
    if test_name == "test0": # just connect
        print("Just connect")
        while True:
            print("Test: just listening")
            worker = WorkerManager(c_config)
            asyncore.loop(timeout=1, map=worker.map)
            time.sleep(1)
        asyncore.loop(timeout=1, map=worker.map)
    elif test_name == 'test1':
        worker = WorkerManager(c_config)

        c_test_thread = WorkerTest('trehad 0', test_name, test_size)
        c_test_thread.start()
        c_test_thread.setworker(worker)

        asyncore.loop(timeout=1, map=worker.map)
    elif test_name == 'test2':
        worker = WorkerManager(c_config)

        thread_pool = []
        for i in range(10):
            thread_pool.append(WorkerTest('thread {0}'.format(i), 'test1', test_size))
            thread_pool[i].setworker(worker)

        for i in range(10):
            thread_pool[i].start()

        asyncore.loop(timeout=1, map=worker.map)
    elif test_name == 'testf':
        worker = WorkerManager(c_config)
        thread_test = WorkerTest(t_name='thread0', test_name='testf', filepath=filepath)
        thread_test.setworker(worker)
        thread_test.start()
        asyncore.loop(timeout=1, map=worker.map)
    elif test_name == 'testc':
        worker = WorkerManager(c_config)
        thread_test = WorkerTest(t_name='thread0', test_name='testc')
        thread_test.setworker(worker)
        thread_test.start()
        asyncore.loop(timeout=1, map=worker.map)
    else:
        print("No test selected")

    print("Exiting...")


#
# Main
#
if __name__ == '__main__':
    myWazuh = Wazuh(get_init=True)

    node_type = sys.argv[1]

    try:
        test_name = sys.argv[2]
    except:
        test_name = "test0"

    try:
        size = int(sys.argv[3])
    except:
        size = 5

    try:
        filepath = sys.argv[3]
    except:
        filepath = ""

    try:
        if  node_type == "master":
            master_main(test_name, size)
        elif node_type == "worker":
            worker_main(test_name, size, filepath)
    except KeyboardInterrupt:
        pass

    print("Bye bye.")
