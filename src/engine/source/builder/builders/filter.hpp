/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _BUILDERS_FILTER_H
#define _BUILDERS_FILTER_H

#include "builders/builders.hpp"
#include "builders/buildCheck.hpp"
#include "builders/stage.hpp"

namespace builder::internals::builders
{
/**
 * @brief Builds rule connectable
 *
 * @param inputJson
 * @return Connectable
 */
Con_t buildFilter(const json::Document & def)
{

    std::vector<std::string> parents;
    const json::Value * name;
    const json::Value * allow;

    auto after = def.get(".after");
    if (!after || !after->IsArray())
    {
        throw std::invalid_argument("Filter builder expects a filter to have an .after array with the names of the "
                                    "assets this filter will be connected to.");
    }

    for (auto & i : after->GetArray())
    {
        parents.push_back(i.GetString());
    }

    try
    {
        name = def.get(".name");
    }
    catch (std::invalid_argument & e)
    {
        std::throw_with_nested(std::invalid_argument("Filter builder expects definition to have a .name entry."));
    }

    try
    {
        allow = def.get(".allow");
    }
    catch (std::invalid_argument & e)
    {
        std::throw_with_nested(std::invalid_argument("Filter builder expects definition to have a .allow section."));
    }

    Op_t checkStage = buildStageChain(allow, buildCheck);

    return Con_t(name->GetString(), parents, [=](const Obs_t & input) -> Obs_t { return checkStage(input); });
};

} // namespace builder::internals::builders
#endif // _BUILDERS_FILTER_H
