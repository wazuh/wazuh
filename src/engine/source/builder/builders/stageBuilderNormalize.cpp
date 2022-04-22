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

#include <logging/logging.hpp>

namespace builder::internals::builders
{

base::Lifter stageBuilderNormalize(const base::DocumentValue & def, types::TracerFn tr)
{
    // Assert value is as expected
    if (!def.IsArray())
    {
        auto msg = fmt::format("Stage normalize builder, expected array but got [{}].", def.GetType());
        WAZUH_LOG_ERROR("{}", msg);
        throw std::invalid_argument(msg);
    }

    // Build all mappings
    std::vector<base::Lifter> mappings;
    for (auto it = def.Begin(); it != def.End(); ++it)
    {
        try
        {
            mappings.push_back(std::get<types::OpBuilder>(Registry::getBuilder("map"))(*it, tr));
        }
        catch (std::exception & e)
        {
            const char* msg = "Stage normalize builder encountered exception on building.";
            WAZUH_LOG_ERROR("{} From exception: [{}]", msg, e.what());
            std::throw_with_nested(std::runtime_error(msg));
        }
    }

    try
    {
        return std::get<types::CombinatorBuilder>(
            Registry::getBuilder("combinator.chain"))(mappings);
    }
    catch(std::exception &e)
    {
        const char *msg = "Stage normalize builder encountered exception "
                          "chaining all mappings.";
        WAZUH_LOG_ERROR("{} From exception: [{}]", msg, e.what());
        std::throw_with_nested(std::runtime_error(msg));
    }
}

} // namespace builder::internals::builders
