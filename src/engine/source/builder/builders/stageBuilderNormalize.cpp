/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "stageBuilderNormalize.hpp"

#include <stdexcept>
#include <string>
#include <vector>

#include "registry.hpp"
#include "stageBuilderCheck.hpp"

#include <logging/logging.hpp>

namespace builder::internals::builders
{

base::Lifter stageBuilderNormalizeMap(const rapidjson::Value &value,
                                       types::TracerFn tr)
{
    std::vector<base::Lifter> mappings;

    // auto mapObject = value.FindMember("map");
    if (value.MemberCount() <= 0)
    {
        throw std::runtime_error("Invalid map");
    }

    if (!value.IsObject())
    {
        throw std::runtime_error("Invalid map object");
    }

    for (rapidjson::Value::ConstMemberIterator it = value.GetObject().MemberBegin(); it != value.GetObject().MemberEnd(); ++it)
    {
        try
        {
            // TODO: Here is an error
            // auto val = std::get<types::OpBuilder>(Registry::getBuilder("map"));
            // auto aux = val(it->value, tr);
            // mappings.push_back(std::get<types::OpBuilder>(
            //     Registry::getBuilder("map"))(it->value, tr));
        }
        catch (std::exception &e)
        {
            WAZUH_LOG_ERROR("Stage normalize builder encountered exception on "
                            "building: [{}]",
                            e.what());

            auto msg = "Stage normalize map builder encountered exception on "
                       "building.";
            std::throw_with_nested(std::runtime_error(msg));
        }
    }

    try
    {
        return std::get<types::CombinatorBuilder>(
            Registry::getBuilder("combinator.chain"))(mappings);
    }
    catch (std::exception &e)
    {
        WAZUH_LOG_ERROR("Stage normalize map builder encountered exception on "
                        "building: [{}]",
                        e.what());

        auto msg =
            "Stage normalize map builder encountered exception on building.";
        std::throw_with_nested(std::runtime_error(msg));
    }
}

base::Lifter
stageBuilderNormalizeConditionalMap(const base::DocumentValue &def,
                                    types::TracerFn tr)
{
    std::vector<base::Lifter> conditionalMappingOps;

    for (auto it = def.Begin(); it != def.End(); ++it)
    {
        if (it->GetString() == "check")
        {
            try
            {
                conditionalMappingOps.push_back(std::get<types::OpBuilder>(
                    Registry::getBuilder("check"))(*it, tr));
            }
            catch (std::exception &e)
            {
                WAZUH_LOG_ERROR("Stage normalize conditional map builder "
                                "encountered exception "
                                "on building: [{}]",
                                e.what());

                auto msg = "Stage normalize conditional map builder "
                           "encountered exception on "
                           "building.";
                std::throw_with_nested(std::runtime_error(msg));
            }
        }
        else if (it->GetString() == "map")
        {
            conditionalMappingOps.push_back(stageBuilderNormalizeMap(*it, tr));
        }
    }

    try
    {
        return std::get<types::CombinatorBuilder>(
            Registry::getBuilder("combinator.chain"))(conditionalMappingOps);
    }
    catch (std::exception &e)
    {
        WAZUH_LOG_ERROR("Stage normalize conditional map builder encountered "
                        "exception on building: [{}]",
                        e.what());

        auto msg = "Stage normalize conditional map builder encountered "
                   "exception on building.";
        std::throw_with_nested(std::runtime_error(msg));
    }
}

base::Lifter stageBuilderNormalize(const base::DocumentValue &def,
                                    types::TracerFn tr)
{
    // Assert value is as expected
    if (!def.IsArray())
    {
        auto msg =
            fmt::format("Stage normalize builder, expected array but got [{}].",
                        def.GetType());
        WAZUH_LOG_ERROR("{}", msg);
        throw std::invalid_argument(msg);
    }

    // Build all the normalize operations
    std::vector<base::Lifter> normalizeOps;

    for (auto it = def.Begin(); it != def.End(); ++it)
    {
        if (it->IsObject())
        {
            if(it->GetObject().HasMember("check"))
            {
                auto a = true;
            }
            if(it->GetObject().HasMember("map"))
            {
                auto a = true;
            }

            if (it->GetObject().HasMember("check") &&
                it->GetObject().HasMember("map"))
            {
                auto a = true;
                normalizeOps.push_back(
                    stageBuilderNormalizeConditionalMap(*it, tr));
            }
            else if (it->GetObject().HasMember("map"))
            {
                auto a = true;
                const auto &test = it->GetObject()["map"];
                normalizeOps.push_back(stageBuilderNormalizeMap(it->GetObject()["map"], tr));
            }
            else
            {
                auto msg =
                    fmt::format("Stage normalize builder, expected either "
                                "\"map\" or \"check\" elements but got [{}].",
                                it->GetString());
                WAZUH_LOG_ERROR("{}", msg);
                throw std::invalid_argument(msg);
            }
        }
        else
        {
            auto msg = fmt::format(
                "Stage normalize builder, expected object but got [{}].",
                it->GetType());
            WAZUH_LOG_ERROR("{}", msg);
            throw std::invalid_argument(msg);
        }
    }

    try
    {
        // Normalize operation (map & check+map) must be completed independently
        return std::get<types::CombinatorBuilder>(
            Registry::getBuilder("combinator.broadcast"))(normalizeOps);
    }
    catch (std::exception &e)
    {
        const char *msg = "Stage normalize builder encountered exception "
                          "chaining all mappings.";
        WAZUH_LOG_ERROR("{} From exception: [{}]", msg, e.what());
        std::throw_with_nested(std::runtime_error(msg));
    }
}

} // namespace builder::internals::builders
