/*
 * Wazuh Validator to validate a configuration file
 * Copyright (C) 2015-2019, Wazuh Inc.
 * September, 2019
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */


#ifndef WIN32
#ifndef _VALIDATOR_H
#define _VALIDATOR_H

int test_manager_conf(const char * path);
int test_agent_conf(const char * path, int type);
int test_remote_conf(const char * path, int type);


#endif
#endif