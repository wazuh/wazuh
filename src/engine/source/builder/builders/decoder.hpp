/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _BUILDERS_DECODER_H
#define _BUILDERS_DECODER_H

#include "builders/builders.hpp"
#include "builders/buildCheck.hpp"
#include "builders/buildMap.hpp"
#include "builders/stage.hpp"

namespace builder::internals::builders
{
/**
 * @brief Builds decoder connectable from the decoder definition.
 *
 * @param def decoder definition
 * @return Con_t
 */
Con_t buildDecoder(const json::Document & def)
{
    const json::Value * name;
    const json::Value * checkVal;
    std::vector<std::string> parents;

    if (def.exists(".parents"))
    {
        for (auto & i : def.get(".parents")->GetArray())
        {
            parents.push_back(i.GetString());
        }
    }

    try
    {
        name = def.get(".name");
    }
    catch (std::invalid_argument & e)
    {
        std::throw_with_nested(std::invalid_argument("Decoder builder expects definition to have a .name entry."));
    }

    try
    {
        checkVal = def.get(".check");
    }
    catch (std::invalid_argument & e)
    {
        std::throw_with_nested(std::invalid_argument("Decoder builder expects definition to have a .allow section."));
    }

    Op_t checkStage = buildStageChain(checkVal, buildCheck);

    // Normalize stage is optional
    Op_t mapStage = unit_op;
    try
    {
        auto mapVal = def.get(".normalize");
        mapStage = buildStageChain(mapVal, buildMap);
    }
    catch (std::invalid_argument & a)
    {
        // normalize stage is optional, in case of an error do nothign
        // we must ensure nothing else could happen here
    }

    return Con_t(name->GetString(), parents, [=](const Obs_t & input) -> Obs_t { return mapStage(checkStage(input)); });
};

} // namespace builder::internals::builders

#endif // _BUILDERS_DECODER_H
