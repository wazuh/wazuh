/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef AGENT_OP_WRAPPERS_H
#define AGENT_OP_WRAPPERS_H

#include "stddef.h"
#include "cJSON.h"

int __wrap_auth_connect();
char* __wrap_get_agent_id_from_name(__attribute__((unused)) char *agent_name);
int __wrap_control_check_connection();

cJSON* __wrap_w_create_sendsync_payload(const char *daemon_name, cJSON *message);
int __wrap_w_send_clustered_message(const char* command, const char* payload, char* response);

#endif
