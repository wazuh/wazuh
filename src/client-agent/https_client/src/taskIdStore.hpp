/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 28, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HC_TASK_ID_STORE_HPP
#define _HC_TASK_ID_STORE_HPP

#include <string>

/**
 * @brief Seam onto the durable, restart-surviving task_id registry.
 *
 * Replaces the in-memory TaskDeduper (retired): the concrete implementation
 * (TaskIdStoreAdapter) round-trips through the C bridge to agent-info's
 * registry (a local IPC hop -- agent-info runs in a separate process,
 * wazuh-modulesd, on Linux/macOS). Tests inject a fake instead.
 *
 * checkAndRecord() is called synchronously on the control thread, once per
 * fresh task_id, BEFORE task batch planning/collapsing and BEFORE dispatch:
 * this ordering guarantee is what makes a remote_upgrade idempotent across
 * the restart it itself triggers.
 */
class ITaskIdStore
{
    public:
        virtual ~ITaskIdStore() = default;

        /// @return true when `taskId` was newly recorded (dispatch it);
        ///         false when it is a duplicate, OR the durable record could
        ///         not be confirmed (e.g. agent-info unreachable) -- fail
        ///         closed: a task whose durability we cannot vouch for must
        ///         not run, since re-dispatch on an IPC hiccup could execute
        ///         a remote_upgrade twice.
        virtual bool checkAndRecord(const std::string& taskId) = 0;
};

#endif // _HC_TASK_ID_STORE_HPP
