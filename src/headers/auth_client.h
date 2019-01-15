/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef __AUTH_CLIENT_H
#define __AUTH_CLIENT_H

// Remove agent. Returns 0 on success or -1 on error.
int auth_remove_agent(int sock, const char *id, int json_format);

#endif /* __AGENT_OP_H */
