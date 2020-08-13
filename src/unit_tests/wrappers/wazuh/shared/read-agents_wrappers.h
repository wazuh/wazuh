/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef READ_AGENTS_WRAPPERS_H
#define READ_AGENTS_WRAPPERS_H

int __wrap_connect_to_remoted();

int __wrap_send_msg_to_agent(int msocket, const char *msg, const char *agt_id, const char *exec);

#endif
