/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "stageBuilderCheck.hpp"

#include <stdexcept>
#include <string>
#include <vector>

#include "registry.hpp"

#include <fmt/format.h>
#include <logging/logging.hpp>

namespace builder::internals::builders
{

base::Lifter stageBuilderCheck(const base::DocumentValue &def,
                                types::TracerFn tr)
{
    // Assert value is as expected
    if (!def.IsArray())
    {
        std::string msg = fmt::format(
            "Stage check builder, expected array but got [{}]", def.GetType());
        WAZUH_LOG_ERROR("{}", msg);
        throw std::invalid_argument(std::move(msg));
    }

    // Build all conditions
    std::vector<base::Lifter> conditions;

    for (auto it = def.Begin(); it != def.End(); ++it)
    {
        try
        {
            conditions.push_back(std::get<types::OpBuilder>(
                Registry::getBuilder("condition"))(*it, tr));
        }
        catch (std::exception &e)
        {
            WAZUH_LOG_ERROR(
                "Stage check builder encountered exception on building: [{}]",
                e.what());

            std::string msg =
                "Stage check builder encountered exception on building.";
            std::throw_with_nested(std::runtime_error(std::move(msg)));
        }
    }

    // Chain all operations
    base::Lifter check;
    try
    {
        check = std::get<types::CombinatorBuilder>(
            Registry::getBuilder("combinator.chain"))(conditions);
    }
    catch (std::exception &e)
    {
        WAZUH_LOG_ERROR("Stage check builder encountered exception chaining "
                        "all conditions: [{}]",
                        e.what());

        std::string msg = "Stage check builder encountered exception chaining "
                          "all conditions.";
        std::throw_with_nested(std::runtime_error(std::move(msg)));
    }

    // Finally return Lifter
    return check;
}

} // namespace builder::internals::builders
