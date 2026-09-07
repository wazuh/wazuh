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

#ifndef _TASK_MANAGER_UPGRADE_REQUEST_PARSER_HPP
#define _TASK_MANAGER_UPGRADE_REQUEST_PARSER_HPP

#include "errorCodes.hpp"
#include "model/task.hpp"

#include <json.hpp>

#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace task_manager::upgrade
{
    /**
     * @brief A parsed `POST /v1/agents/upgrade` body.
     */
    struct UpgradeRequest
    {
        std::vector<int> agentIds;
        Timestamp requestTime {0};
        /// @brief The `wpk_repo` parameter.
        std::string wpkRepository;
        /// @brief The `version` parameter -- the version to install, when the caller names one.
        std::string customVersion;
        /// @brief The `package_type` parameter: "rpm" or "deb" only.
        std::string packageType;
        bool useHttp {false};
        bool forceUpgrade {false};
    };

    /**
     * @brief A parsed `POST /v1/agents/upgrade-custom` body.
     */
    struct UpgradeCustomRequest
    {
        std::vector<int> agentIds;
        Timestamp requestTime {0};
        std::string filePath;
        std::string installer;
    };

    /**
     * @brief Why a body was rejected.
     *
     * `message` overrides the code's own text in the per-agent data entry while the envelope's
     * top-level message still comes from the code -- exactly the two-level shape the retired parser
     * produced, and which the Server API surfaces to the user verbatim.
     */
    struct ParseFailure
    {
        UpgradeError error {UpgradeError::ParsingRequiredParameter};
        std::string message;
    };

    template<typename T>
    struct ParseResult
    {
        std::optional<T> value;
        ParseFailure failure;

        bool ok() const
        {
            return value.has_value();
        }
    };

    /**
     * @brief Parse the shared `agents` array.
     *
     * Every element must be a positive integer. A missing, non-array or empty `agents` is
     * ParsingRequiredParameter with the code's own message; a bad element is TaskConfigurations with
     * "Agent id not recognized". Both strings are wire format.
     */
    ParseResult<std::vector<int>> parseAgentIds(const nlohmann::json& body);

    /**
     * @brief Parse an upgrade body.
     *
     * Recognised keys: request_time, wpk_repo, version, use_http, force_upgrade, package_type.
     * `request_time` is mandatory -- it is the only source of the deterministic task id that makes
     * the same request idempotent across cluster nodes -- and must fall inside the same
     * [now - MAX_AGE, now + MAX_FUTURE_SKEW] window the agent-task create route enforces.
     *
     * UNRECOGNISED KEYS ARE IGNORED, deliberately. A misspelled "forse_upgrade" is accepted and the
     * upgrade proceeds unforced. This is preserved rather than tightened: callers ahead of this
     * manager's version legitimately send keys it does not know yet, and rejecting them would break
     * a newer API against an older manager.
     *
     * @param now Current time, injected so the window is testable without waiting for a clock.
     */
    ParseResult<UpgradeRequest> parseUpgradeRequest(const nlohmann::json& body, Timestamp now);

    /**
     * @brief Parse an upgrade-custom body. Recognised keys: request_time, file_path, installer.
     */
    ParseResult<UpgradeCustomRequest> parseUpgradeCustomRequest(const nlohmann::json& body, Timestamp now);
} // namespace task_manager::upgrade

#endif // _TASK_MANAGER_UPGRADE_REQUEST_PARSER_HPP
