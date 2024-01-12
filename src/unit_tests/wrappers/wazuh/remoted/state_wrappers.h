/*
 * Wazuh Shared Configuration Manager
 * Copyright (C) 2015, Wazuh Inc.
 * May 19, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef REM_STATE_WRAPPERS_H
#define REM_STATE_WRAPPERS_H

#include <cJSON.h>

void __wrap_rem_add_recv(unsigned long bytes);

void __wrap_rem_inc_tcp();

void __wrap_rem_dec_tcp();

void __wrap_rem_inc_recv_evt();

void __wrap_rem_inc_recv_ctrl(const char *agent_id);

void __wrap_rem_inc_recv_ctrl_request(const char *agent_id);

void __wrap_rem_inc_recv_ctrl_startup(const char *agent_id);

void __wrap_rem_inc_recv_ctrl_shutdown(const char *agent_id);

void __wrap_rem_inc_recv_ctrl_keepalive(const char *agent_id);

void __wrap_rem_inc_recv_unknown();

void __wrap_rem_add_send(unsigned long bytes);

void __wrap_rem_inc_send_ack(const char *agent_id);

void __wrap_rem_inc_send_discarded(const char *agent_id);

cJSON* __wrap_rem_create_state_json();

cJSON* __wrap_rem_create_agents_state_json(int *agents_ids);

#endif /* REM_STATE_WRAPPERS_H */
