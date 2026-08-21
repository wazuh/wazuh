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
 * @brief Why startup_gate_wait_for_ready() returned.
 *
 * A caller MUST check this before running its module's actual start routine:
 * STARTUP_GATE_SHUTDOWN_REQUESTED means a shutdown is already in progress, and
 * the module must abort its startup cleanly instead of starting (issue 38428
 * - previously the gate released on shutdown exactly as if it had opened
 * normally, with no way for the caller to tell the two apart).
 */
typedef enum startup_gate_wait_result {
    STARTUP_GATE_READY = 0,             /**< Gate opened normally; proceed with startup. */
    STARTUP_GATE_SHUTDOWN_REQUESTED = 1 /**< Shutdown already in progress; abort startup, do not run the module. */
} startup_gate_wait_result_t;

/**
 * @brief Block a daemon startup until agentd startup hash validation is ready.
 *
 * This function is a no-op (always returns STARTUP_GATE_READY) when startup
 * hash blocking is disabled, or on a non-CLIENT (manager) build.
 *
 * @param module_name Daemon name for logs.
 * @return STARTUP_GATE_READY if the caller should proceed with its normal
 *         startup, or STARTUP_GATE_SHUTDOWN_REQUESTED if a shutdown is
 *         already in progress and the caller must abort cleanly instead.
 */
startup_gate_wait_result_t startup_gate_wait_for_ready(const char *module_name);

#endif /* STARTUP_GATE_OP_H */
