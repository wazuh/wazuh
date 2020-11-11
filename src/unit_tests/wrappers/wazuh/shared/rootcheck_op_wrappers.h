/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef ROOTCHECK_OP_WRAPPERS
#define ROOTCHECK_OP_WRAPPERS

int __wrap_send_rootcheck_log(const char* agent_id, long int date, const char* log, char* response);


#endif
