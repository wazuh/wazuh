/*
 * URL download support library
 * Copyright (C) 2015, Wazuh Inc.
 * April 3, 2018.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef CLUSTER_UTILS_H_
#define CLUSTER_UTILS_H_

// Returns 1 if the node is a worker, 0 if it is not and -1 if error.
int w_is_worker(void);

/**
 * @brief Method to read the configuration file and determine if the cluster is enabled or not. It's also possible
 *        to know if the current node is a worker or the master.
 *
 * @param [out] is_worker If the cluster is enabled, a 1 will be written in case it's a worker node and 0 if it's the
 * master. OS_INVALID otherwise.
 * @return int It'll return 1 if the cluster is enabled or 0 if it isn't. OS_INVALID if the information isn't available.
 */
int w_is_single_node(int* is_worker);

// Returns the master node or "undefined" if any node is specified. The memory should be freed by the caller.
char* get_master_node(void);

// Returns the node name of the manager in cluster. The memory should be freed by the caller.
char* get_node_name(void);

// Returns the name of the manager in cluster. The memory should be freed by the caller.
char* get_cluster_name(void);

// Returns the cluster status. 1 if the cluster is enabled, 0 if it isn't.
bool get_cluster_status(void);

#endif
