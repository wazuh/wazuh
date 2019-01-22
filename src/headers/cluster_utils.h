/*
 * URL download support library
 * Copyright (C) 2015-2019, Wazuh Inc.
 * April 3, 2018.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef CLUSTER_UTILS_H_
#define CLUSTER_UTILS_H_

// Returns 1 if the node is a worker, 0 if it is not and -1 if error.
int w_is_worker(void);

// Returns the master node or "undefined" if any node is specified.
char *get_master_node(void);

#endif
