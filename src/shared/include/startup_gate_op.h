/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef STARTUP_GATE_OP_H
#define STARTUP_GATE_OP_H

/**
 * @brief Block a daemon startup until agentd startup hash validation is ready.
 *
 * This function is a no-op when startup hash blocking is disabled.
 *
 * @param module_name Daemon name for logs.
 */
void startup_gate_wait_for_ready(const char *module_name);

#endif /* STARTUP_GATE_OP_H */
