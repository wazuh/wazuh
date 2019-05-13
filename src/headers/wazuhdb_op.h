/*
 * Copyright (C) 2015-2019, Wazuh Inc.
 * April 15, 2019.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "os_net/os_net.h"


int wdb_send_query(char *wazuhdb_query, char **output);