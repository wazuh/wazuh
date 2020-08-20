/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef MQ_OP_WRAPPERS_H
#define MQ_OP_WRAPPERS_H

int __wrap_SendMSG(int queue, const char *message, const char *locmsg, char loc);

int __wrap_StartMQ(const char *path, short int type, short int n_attempts);

#endif
