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
 * @brief Allocate the pending clear_upgrade_result reply queue.
 *
 * Must be called before the poller thread (legacy_upgrade_task_delivery) is started and before
 * the rem_handler worker pool that calls legacy_task_process_upgrade_ack() is created, since both
 * touch the queue.
 */
void legacy_task_delivery_init(void);

/**
 * @brief Drain and free the pending clear_upgrade_result reply queue.
 *
 * Not wired into any daemon shutdown path today; provided for test cleanup, same as
 * agent_metadata_teardown().
 */
void legacy_task_delivery_teardown(void);

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

/**
 * @brief Process a legacy agent's `upgrade_update_status` ack.
 *
 * A pre-v5.0.0 agent resends this ack on a backoff loop until it receives an explicit
 * `clear_upgrade_result` command back -- see wm_agent_upgrade_check_status() (agent-side,
 * unmodified). This only confirms the ack is a well-formed `upgrade_update_status` message and
 * replies with `clear_upgrade_result` so the agent stops retrying; it does not touch any task's
 * stored status -- `delivered` is the Task Manager's own terminal state for a legacy push, by
 * design (the agent's own durable dedup is what guards against a duplicate/late redelivery, not
 * a manager-side status field).
 *
 * @param agent_id Agent identifier.
 * @param ack_json The ack's JSON body, with the `u:upgrade_module:` header already stripped.
 * @return true if the ack was a recognized `upgrade_update_status` message and was replied to;
 * false if it was malformed/unrecognized and ignored.
 */
bool legacy_task_process_upgrade_ack(const char *agent_id, const char *ack_json) __attribute__((nonnull));

#endif /* LEGACY_TASK_DELIVERY_H */
