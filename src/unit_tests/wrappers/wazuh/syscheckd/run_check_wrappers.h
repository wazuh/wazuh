/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef RUN_CHECK_WRAPPERS_H
#define RUN_CHECK_WRAPPERS_H

#include "../../../../syscheckd/include/syscheck.h"

int __wrap_send_log_msg(const char * msg);

void __wrap_send_syscheck_msg(char *msg);

void __wrap_fim_sync_check_eps();

// Send a state synchronization message
void __wrap_fim_send_sync_state(const char* location, const char* msg);

#endif
