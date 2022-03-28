/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "stageBuilderOutputs.hpp"

#include <stdexcept>
#include <string>
#include <vector>

#include "registry.hpp"

#include <logging/logging.hpp>

namespace builder::internals::builders
{

types::Lifter stageBuilderOutputs(const types::DocumentValue & def, types::TracerFn tr)
{
    // Assert value is as expected
    if (!def.IsArray())
    {
        auto msg =
            fmt::format("Stage outputs builder, expected array but got [{}]",
                        def.GetType());
        WAZUH_LOG_ERROR("{}", msg);
        throw std::invalid_argument(msg);
    }

    // Build all outputs
    std::vector<types::Lifter> outputs;
    for (auto it = def.Begin(); it != def.End(); ++it)
    {
        try
        {
            outputs.push_back(std::get<types::OpBuilder>(Registry::getBuilder(it->MemberBegin()->name.GetString()))(it->MemberBegin()->value, tr));
        }
        catch (std::exception & e)
        {
            const char* msg = "Stage outputs builder encountered exception on building.";
            WAZUH_LOG_ERROR("{} From exception: [{}]", msg, e.what());
            std::throw_with_nested(std::runtime_error(msg));
        }
    }

    // Broadcast to all operations
    types::Lifter output;
    try
    {
        output = std::get<types::CombinatorBuilder>(Registry::getBuilder("combinator.broadcast"))(outputs);
    }
    catch (std::exception & e)
    {
        const char* msg = "Stage outputs builder encountered exception broadcasting all outputs.";
        WAZUH_LOG_ERROR("{} From exception: [{}]", msg, e.what());
        std::throw_with_nested(std::runtime_error(msg));
    }

    // Finally return Lifter
    return output;
}

} // namespace builder::internals::builders
