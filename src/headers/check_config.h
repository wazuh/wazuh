/*
 * Wazuh Check Configuration file
 * Copyright (C) 2015-2019, Wazuh Inc.
 * September, 2019
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */


#ifndef WIN32

#ifndef CHECK_CONFIG_H
#define CHECK_CONFIG_H

#define CHK_CONFIG_INFO  "check_config: "
#define CHK_CONFIG_ERR   "check_config: ERROR: "

#include "shared.h"
#include "config/config.h"

int test_manager_conf(const char *path, char **output);
int test_agent_conf(const char *path, int type, char **output);
int test_remote_conf(const char *path, int type, char **output);
int validate_target(const char *path, int type, char **output);


#endif
#endif