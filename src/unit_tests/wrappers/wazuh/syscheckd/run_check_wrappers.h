/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef RUN_CHECK_WRAPPERS_H
#define RUN_CHECK_WRAPPERS_H

#include "syscheckd/syscheck.h"

void __wrap_fim_send_scan_info(fim_scan_event event);

void __wrap_fim_send_sync_msg(const char * msg);

int __wrap_send_log_msg(const char * msg);

void __wrap_send_syscheck_msg(char *msg);

#endif
