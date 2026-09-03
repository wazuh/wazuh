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

#include "requestParser.hpp"

namespace
{
    using namespace task_manager;
    using namespace task_manager::upgrade;

    /// @brief Wire-format strings. Every one of these reaches a user through the Server API verbatim.
    ParseFailure typeFailure(const char* key, const char* expectation)
    {
        return {UpgradeError::TaskConfigurations,
                std::string {"Parameter \""} + key + "\" should be " + expectation};
    }

    /**
     * @brief Read an optional string field, failing when it is present with the wrong type.
     *
     * @return false when the field failed; `failure` is then set.
     */
    bool readString(const nlohmann::json& body, const char* key, std::string& out, ParseFailure& failure)
    {
        const auto it {body.find(key)};
        if (it == body.end())
        {
            return true;
        }

        if (!it->is_string())
        {
            failure = typeFailure(key, "a string");
            return false;
        }

        out = it->get<std::string>();
        return true;
    }

    bool readBool(const nlohmann::json& body, const char* key, bool& out, ParseFailure& failure)
    {
        const auto it {body.find(key)};
        if (it == body.end())
        {
            return true;
        }

        if (!it->is_boolean())
        {
            failure = typeFailure(key, "true or false");
            return false;
        }

        out = it->get<bool>();
        return true;
    }

    /**
     * @brief Read and validate `request_time`, which every upgrade body must carry.
     *
     * Two distinct rejections, and the difference matters. A missing or wrong-typed value reproduces
     * the retired parser exactly, down to the code and the string. An out-of-window value is a NEW
     * check: the agent-task create route already enforced this window, so without it the same
     * request would be admitted here and refused there, having resolved to the same task id.
     */
    bool readRequestTime(const nlohmann::json& body, const Timestamp now, Timestamp& out, ParseFailure& failure)
    {
        const auto it {body.find("request_time")};
        if (it == body.end())
        {
            failure = {UpgradeError::TaskConfigurations, "Missing required parameter: request_time"};
            return false;
        }

        if (!it->is_number())
        {
            failure = typeFailure("request_time", "a number");
            return false;
        }

        out = static_cast<Timestamp>(it->get<double>());

        // Zero is how the retired parser spelled "absent", and it is also a timestamp no caller can
        // legitimately mean, so it keeps the original message rather than the window one.
        if (out == 0)
        {
            failure = {UpgradeError::TaskConfigurations, "Missing required parameter: request_time"};
            return false;
        }

        if (out > now + MAX_FUTURE_SKEW)
        {
            failure = {UpgradeError::ParsingRequiredParameter, "Parameter \"request_time\" is in the future"};
            return false;
        }

        if (out < now - MAX_AGE)
        {
            failure = {UpgradeError::ParsingRequiredParameter, "Parameter \"request_time\" is too old (>1 year)"};
            return false;
        }

        return true;
    }
} // namespace

namespace task_manager::upgrade
{
    ParseResult<std::vector<int>> parseAgentIds(const nlohmann::json& body)
    {
        ParseResult<std::vector<int>> result;

        const auto it {body.find("agents")};
        if (it == body.end() || !it->is_array() || it->empty())
        {
            result.failure = {UpgradeError::ParsingRequiredParameter, ""};
            return result;
        }

        std::vector<int> agentIds;
        agentIds.reserve(it->size());

        for (const auto& agent : *it)
        {
            // is_number_integer() rejects 5.5 where the retired cJSON check accepted it and
            // truncated through valueint. A fractional agent id is a caller bug either way, and
            // silently upgrading agent 5 because 5.5 was asked for is the worse of the two answers.
            if (!agent.is_number_integer() || agent.get<long long>() <= 0 ||
                agent.get<long long>() > std::numeric_limits<int>::max())
            {
                result.failure = {UpgradeError::TaskConfigurations, "Agent id not recognized"};
                return result;
            }
            agentIds.push_back(agent.get<int>());
        }

        result.value = std::move(agentIds);
        return result;
    }

    ParseResult<UpgradeRequest> parseUpgradeRequest(const nlohmann::json& body, const Timestamp now)
    {
        ParseResult<UpgradeRequest> result;

        if (!body.is_object())
        {
            result.failure = {UpgradeError::ParsingRequiredParameter, ""};
            return result;
        }

        auto agents {parseAgentIds(body)};
        if (!agents.ok())
        {
            result.failure = std::move(agents.failure);
            return result;
        }

        UpgradeRequest request;
        request.agentIds = std::move(*agents.value);

        // Fixed order rather than document order. The retired parser walked the object and reported
        // whichever bad key came first, which for a body with two bad keys made the message depend
        // on the caller's serialisation order.
        if (!readRequestTime(body, now, request.requestTime, result.failure) ||
            !readString(body, "wpk_repo", request.wpkRepository, result.failure) ||
            !readString(body, "version", request.customVersion, result.failure) ||
            !readBool(body, "use_http", request.useHttp, result.failure) ||
            !readBool(body, "force_upgrade", request.forceUpgrade, result.failure) ||
            !readString(body, "package_type", request.packageType, result.failure))
        {
            return result;
        }

        if (!request.packageType.empty() && request.packageType != "rpm" && request.packageType != "deb")
        {
            result.failure = {UpgradeError::TaskConfigurations,
                              "Invalid parameter \"package_type\", value should be \"rpm\" or \"deb\""};
            return result;
        }

        result.value = std::move(request);
        return result;
    }

    ParseResult<UpgradeCustomRequest> parseUpgradeCustomRequest(const nlohmann::json& body, const Timestamp now)
    {
        ParseResult<UpgradeCustomRequest> result;

        if (!body.is_object())
        {
            result.failure = {UpgradeError::ParsingRequiredParameter, ""};
            return result;
        }

        auto agents {parseAgentIds(body)};
        if (!agents.ok())
        {
            result.failure = std::move(agents.failure);
            return result;
        }

        UpgradeCustomRequest request;
        request.agentIds = std::move(*agents.value);

        if (!readRequestTime(body, now, request.requestTime, result.failure) ||
            !readString(body, "file_path", request.filePath, result.failure) ||
            !readString(body, "installer", request.installer, result.failure))
        {
            return result;
        }

        result.value = std::move(request);
        return result;
    }
} // namespace task_manager::upgrade
