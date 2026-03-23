/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef AGENTD_SENDMSG_H
#define AGENTD_SENDMSG_H

#include "agentd.h"

/* Send message to server */
int send_msg(const char* msg, ssize_t msg_length);

#endif /* AGENTD_SENDMSG_H */
