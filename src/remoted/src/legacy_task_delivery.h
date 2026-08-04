/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef LEGACY_TASK_DELIVERY_H
#define LEGACY_TASK_DELIVERY_H

/**
 * @brief Poller thread entry point.
 *
 * Periodically walks the currently-connected agents and, for every one
 * confirmed to be below v5.0.0, asks the Task Manager for its pending tasks
 * and delivers any `remote_upgrade` ones over the agent's existing session
 * using the legacy six-step WPK push. Every other task type returned by the
 * poll is logged and dropped. Never returns.
 *
 * @param arg Unused.
 * @return Never returns (NULL is unreachable).
 */
void *legacy_upgrade_task_delivery(void *arg);

#endif /* LEGACY_TASK_DELIVERY_H */
