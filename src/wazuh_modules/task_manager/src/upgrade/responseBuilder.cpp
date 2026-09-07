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

#include "responseBuilder.hpp"

#include <json.hpp>

namespace
{
    using namespace task_manager::upgrade;

    /**
     * @brief One `data` entry: error, then message, then agent -- in that order.
     *
     * ordered_json, not json, throughout this file. The default json is backed by std::map and would
     * emit keys alphabetically, turning {"error":..,"message":..,"agent":..} into
     * {"agent":..,"error":..,"message":..}. No JSON parser cares, but the golden-byte test that
     * proves this envelope still matches the retired C's output does, and that test is the cheapest
     * guard the Server API contract has.
     */
    nlohmann::ordered_json dataEntry(const UpgradeError error, const std::string& message)
    {
        nlohmann::ordered_json entry;
        entry["error"] = errorValue(error);
        entry["message"] = message.empty() ? errorMessage(error) : message.c_str();
        return entry;
    }

    std::string envelope(const UpgradeError error, nlohmann::ordered_json data)
    {
        nlohmann::ordered_json response;
        response["error"] = errorValue(error);
        response["data"] = std::move(data);
        // Always the code's own text, never the custom one -- see buildFailureResponse().
        response["message"] = errorMessage(error);
        return response.dump();
    }
} // namespace

namespace task_manager::upgrade
{
    std::string buildResponse(const UpgradeError envelopeError, const std::vector<AgentOutcome>& outcomes)
    {
        // `=`, not braces, for every json here. `auto data {json::array()}` would select the
        // initializer-list constructor and build [[]] -- the module's usual brace-init style is a
        // trap on this one type, and it produces a well-formed response with the wrong shape.
        auto data = nlohmann::ordered_json::array();

        for (const auto& outcome : outcomes)
        {
            auto entry = dataEntry(outcome.error, outcome.message);
            entry["agent"] = outcome.agentId;
            data.push_back(std::move(entry));
        }

        return envelope(envelopeError, std::move(data));
    }

    std::string buildFailureResponse(const UpgradeError error, const std::string& message)
    {
        auto data = nlohmann::ordered_json::array();
        data.push_back(dataEntry(error, message));
        return envelope(error, std::move(data));
    }

    std::string buildUniformResponse(const UpgradeError error, const std::vector<int>& agentIds)
    {
        std::vector<AgentOutcome> outcomes;
        outcomes.reserve(agentIds.size());

        for (const int agentId : agentIds)
        {
            outcomes.push_back({agentId, error, {}});
        }

        // Success at the top level even though every agent failed: the retired code reported the
        // envelope code as Success for anything it managed to answer per agent, and the Server API
        // only ever reads the per-agent entries.
        return buildResponse(UpgradeError::Success, outcomes);
    }
} // namespace task_manager::upgrade
