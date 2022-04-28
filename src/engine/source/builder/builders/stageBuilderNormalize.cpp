/* Copyright (C) 2015-2022, Wazuh Inc.
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

#include "combinatorBuilderBroadcast.hpp"
#include "combinatorBuilderChain.hpp"
#include "opBuilderMap.hpp"
#include "registry.hpp"
#include "stageBuilderCheck.hpp"

#include <logging/logging.hpp>

namespace builder::internals::builders
{

using types::CombinatorBuilder;
using base::DocumentValue;
using base::Lifter;
using types::TracerFn;

using std::invalid_argument;
using std::runtime_error;
using std::throw_with_nested;

static Lifter normalizeMap(const DocumentValue &ref, TracerFn tr)
{
    if (!ref.IsObject())
    {
        auto msg = "Invalid \"map\" element, it should be an object.";
        WAZUH_LOG_ERROR("{}", msg);
        throw_with_nested(invalid_argument(msg));
    }

    if (ref.MemberCount() <= 0)
    {
        auto msg = "Invalid \"map\" element, it can not be empty.";
        WAZUH_LOG_ERROR("{}", msg);
        throw_with_nested(invalid_argument(msg));
    }

    // These are necessary to create the object to be sent to the map operation
    base::Document doc;
    auto docAllocator = doc.getAllocator();

    // Gets the "map" object
    auto mapObject = ref.GetObject();

    std::vector<Lifter> mapOps;

    // Iterates through the "map" object's members
    for (auto it = mapObject.MemberBegin(); it != mapObject.MemberEnd(); ++it)
    {
        try
        {
            /** TODO: This is a temporary (naive) solution to handle the
             * mapping. As the mapping methods expect an object, it is necessary
             * to construct one with the key and value pair.
             */
            rapidjson::Value pairKeyValue(rapidjson::kObjectType);
            DocumentValue val(it->value, docAllocator);
            DocumentValue key(it->name, docAllocator);
            pairKeyValue.AddMember(key.Move(), val.Move(), docAllocator);
            mapOps.push_back(opBuilderMap(pairKeyValue, tr));
        }
        catch (std::exception &e)
        {
            auto msg = fmt::format("Stage normalize builder encountered "
                                   "exception on building: [{}]",
                                   e.what());
            WAZUH_LOG_ERROR("{}", msg);
            throw_with_nested(runtime_error(msg));
        }
    }

    try
    {
        // Chains the "map" operations
        return combinatorBuilderChain(mapOps);
    }
    catch (std::exception &e)
    {
        auto msg = fmt::format(
            "Stage normalize builder encountered exception on building: [{}]",
            e.what());
        WAZUH_LOG_ERROR("{}", msg);
        throw_with_nested(runtime_error(msg));
    }
}

static Lifter normalizeCheck(const DocumentValue &ref, TracerFn tr)
{
    if (!ref.IsArray())
    {
        auto msg = "Invalid \"check\" object, it should be an array.";
        WAZUH_LOG_ERROR("{}", msg);
        throw_with_nested(invalid_argument(msg));
    }

    // Gets the "check" array
    auto checkArray = ref.GetArray();

    if (checkArray.Capacity() <= 0)
    {
        auto msg = "Invalid \"check\" object, it can not be empty.";
        WAZUH_LOG_ERROR("{}", msg);
        throw_with_nested(invalid_argument(msg));
    }

    std::vector<Lifter> checkOps;

    try
    {
        checkOps.push_back(stageBuilderCheck(checkArray, tr));
    }
    catch (std::exception &e)
    {
        auto msg = fmt::format("Stage normalize builder encountered "
                               "exception on building: [{}]",
                               e.what());
        WAZUH_LOG_ERROR("{}", msg);
        throw_with_nested(runtime_error(msg));
    }

    try
    {
        // Chains the "check" operations
        return combinatorBuilderChain(checkOps);
    }
    catch (std::exception &e)
    {
        auto msg = fmt::format(
            "Stage normalize builder encountered exception on building: [{}]",
            e.what());
        WAZUH_LOG_ERROR("{}", msg);
        throw_with_nested(runtime_error(msg));
    }
}

static Lifter normalizeConditionalMap(const DocumentValue &def, TracerFn tr)
{
    // Normalize stage must always have exactly two elements: "check" and "map"
    if (def.MemberCount() != 2)
    {
        auto msg = fmt::format(
            "Invalid conditional map configuration, two (2) elements "
            "were expected, \"check\" and \"map\", but got: {}",
            def.MemberCount());
        WAZUH_LOG_ERROR("{}", msg);
        throw_with_nested(invalid_argument(msg));
    }

    std::vector<Lifter> conditionalMapOps;

    try
    {
        // First chain the "check" operations
        conditionalMapOps.push_back(normalizeCheck(def["check"], tr));
    }
    catch (std::exception &e)
    {
        auto msg = fmt::format(
            "Stage normalize conditional map builder "
            "encountered exception on building the \"check\" object: [{}].",
            e.what());
        WAZUH_LOG_ERROR("{}", msg);
        throw_with_nested(runtime_error(msg));
    }

    try
    {
        // Second chain the "map" operations
        conditionalMapOps.push_back(normalizeMap(def["map"], tr));
    }
    catch (std::exception &e)
    {
        auto msg = fmt::format(
            "Stage normalize conditional map builder "
            "encountered exception on building the \"map\" object: [{}].",
            e.what());
        WAZUH_LOG_ERROR("{}", msg);
        throw_with_nested(runtime_error(msg));
    }

    try
    {
        /** The "check" and "map" operations are chained (in that order) so if a
         * check fails, then the pipeline aborts its flow. If all the checks
         * pass, then the pipeline performs the "map" operations. */
        return combinatorBuilderChain(conditionalMapOps);
    }
    catch (std::exception &e)
    {
        auto msg = fmt::format("Stage normalize conditional map builder "
                               "encountered exception on building: [{}]",
                               e.what());
        WAZUH_LOG_ERROR("{}", msg);
        throw_with_nested(runtime_error(msg));
    }
}

Lifter stageBuilderNormalize(const DocumentValue &def, TracerFn tr)
{
    bool doMap = false;
    bool doConditionalMap = false;

    // Assert value is as expected
    if (!def.IsArray())
    {
        auto msg = fmt::format("Stage normalize builder, expected "
                               "\"normalize\" to be an array but got [{}].",
                               def.GetType());
        WAZUH_LOG_ERROR("{}", msg);
        throw_with_nested(invalid_argument(msg));
    }

    // Build all the normalize operations
    std::vector<Lifter> normalizeOps;

    for (auto it = def.Begin(); it != def.End(); ++it)
    {
        if (it->IsObject())
        {
            auto obj = it->GetObject();

            if (obj.HasMember("map"))
            {
                if (obj.HasMember("check"))
                {
                    if (doConditionalMap)
                    {
                        auto msg = fmt::format(
                            "Stage normalize builder, expected only one "
                            "conditional map but got more than one.");
                        WAZUH_LOG_ERROR("{}", msg);
                        throw_with_nested(invalid_argument(msg));
                    }
                    else
                    {
                        normalizeOps.push_back(
                            normalizeConditionalMap(obj, tr));
                        doConditionalMap = true;
                    }
                }
                else
                {
                    if (obj.MemberCount() != 1)
                    {
                        auto msg = fmt::format(
                            "Stage normalize builder, expected only a"
                            "\"map\" object but got more than one objects.");
                        WAZUH_LOG_ERROR("{}", msg);
                        throw_with_nested(invalid_argument(msg));
                    }
                    else
                    {
                        if (doMap)
                        {
                            auto msg = fmt::format(
                                "Stage normalize builder, expected only one "
                                "\"map\" object but got more than one.");
                            WAZUH_LOG_ERROR("{}", msg);
                            throw_with_nested(invalid_argument(msg));
                        }
                        else
                        {
                            normalizeOps.push_back(
                                normalizeMap(obj["map"], tr));
                            doMap = true;
                        }
                    }
                }
            }
            else
            {
                auto msg = "Stage normalize builder, there is a conditional "
                           "map object with no \"map\" element on it.";
                WAZUH_LOG_ERROR("{}", msg);
                throw_with_nested(invalid_argument(msg));
            }
        }
        else
        {
            auto msg =
                fmt::format("Stage normalize builder, each \"normalize\" array "
                            "element should be an object but got [{}].",
                            it->GetType());
            WAZUH_LOG_ERROR("{}", msg);
            throw_with_nested(invalid_argument(msg));
        }
    }

    try
    {
        /** The normalize operations will only be broadcasted if both the "map"
         * (inconditional) and "conditional map" are present, as the conditional
         * map could abort the pipeline flow. */
        if (doMap && doConditionalMap)
        {
            /** As the map and check-map (conditional map) operations run in
             * parallel, some special considerations must be taken. The map one
             * always produces an output and modifies the input object while the
             * check-map operation may not produce any output. To handle this
             * situation, these operations can not be serialized (chained) so
             * they should be combined with the broadcast operation. This leads
             * to another situation, only one observable should be emitted so
             * both outputs should be filtered and a dummy one had to be created
             * to publish the result. */
            for (auto &op : normalizeOps)
            {
                op = [op](base::Observable in)
                {
                    // Filter map and check-map outputs
                    return op(in).filter([](auto) { return false; });
                };
            }
            // Append a dummy observable publisher to the list of operations
            normalizeOps.push_back([](base::Observable in) { return in; });

            // Combine the normalize operations as broadcast
            return combinatorBuilderBroadcast(normalizeOps);
        }
        return normalizeOps.back();
    }
    catch (std::exception &e)
    {
        auto msg = fmt::format("Stage normalize builder encountered exception "
                               "on building: [{}]",
                               e.what());
        WAZUH_LOG_ERROR("{}", msg);
        throw_with_nested(runtime_error(msg));
    }
}

} // namespace builder::internals::builders
