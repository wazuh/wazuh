/*
 * Wazuh task manager module
 * Copyright (C) 2015, Wazuh Inc.
 * September 3, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _TASK_MANAGER_UPGRADE_RESPONSE_BUILDER_HPP
#define _TASK_MANAGER_UPGRADE_RESPONSE_BUILDER_HPP

#include "errorCodes.hpp"

#include <string>
#include <vector>

namespace task_manager::upgrade
{
    /**
     * @brief One agent's verdict.
     */
    struct AgentOutcome
    {
        int agentId {0};
        UpgradeError error {UpgradeError::Success};
        /// @brief Overrides the code's own message when non-empty.
        std::string message;
    };

    /**
     * @brief Build the per-agent response envelope.
     *
     * THE EXACT BYTES MATTER. This is what the Server API reads:
     *
     *   {"error":0,
     *    "data":[{"error":0,"message":"Success","agent":4},
     *            {"error":12,"message":"The repository is not reachable","agent":5}],
     *    "message":"Success"}
     *
     * framework/wazuh/agent.py turns each data entry into `1810 + error` and lifts `message`
     * verbatim, because none of 1810..1828 has an entry in exception.py. Key order, key names and
     * the presence of the redundant top-level `message` are all part of the contract that keeps the
     * existing tavern suites passing unmodified.
     *
     * @param envelopeError The top-level code. Success for a per-agent response, whatever went wrong
     *                      for a whole-request failure -- the retired code reported Success at the
     *                      top level even when every agent failed, and that is preserved.
     */
    std::string buildResponse(UpgradeError envelopeError, const std::vector<AgentOutcome>& outcomes);

    /**
     * @brief Build a whole-request failure envelope: one data entry, no `agent` key.
     *
     * Used for a body that could not be parsed at all, for a disabled module, and for shutdown --
     * every case where there is no per-agent verdict to report because no agent was ever examined.
     *
     * @param message Overrides the code's own message when non-empty. The top-level `message` always
     *                comes from the code, so a custom string appears ONLY in the data entry. That
     *                two-level split is the retired shape and callers parse both halves.
     */
    std::string buildFailureResponse(UpgradeError error, const std::string& message);

    /**
     * @brief Build a failure envelope carrying one data entry per agent, all with the same verdict.
     *
     * For failures that are known to affect the whole batch but where the caller still needs an
     * entry per agent to reconcile against what it sent -- a store rollback, or a shutdown that
     * caught a batch whose agents had already been accepted.
     */
    std::string buildUniformResponse(UpgradeError error, const std::vector<int>& agentIds);
} // namespace task_manager::upgrade

#endif // _TASK_MANAGER_UPGRADE_RESPONSE_BUILDER_HPP
