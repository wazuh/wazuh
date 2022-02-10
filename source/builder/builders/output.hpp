/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _BUILDERS_OUTPUT_H
#define _BUILDERS_OUTPUT_H

#include "builders/builders.hpp"
#include "builders/buildCheck.hpp"
#include "builders/buildOutput.hpp"
#include "builders/stage.hpp"

namespace builder::internals::builders
{
/**
 * @brief Builds output connectable
 *
 * @param inputJson
 * @return Connectable
 */
Con_t buildOutput(const json::Document & def)
{
    std::vector<std::string> parents;
    const json::Value * name;
    const json::Value * checkVal;
    const json::Value * outputs;

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
        std::throw_with_nested(std::invalid_argument("Output builder expects definition to have a .name entry."));
    }

    try
    {
        checkVal = def.get(".check");
    }
    catch (std::invalid_argument & e)
    {
        std::throw_with_nested(std::invalid_argument("Output builder expects definition to have a .allow section."));
    }

    Op_t checkStage = buildStageChain(checkVal, buildCheck);

    try
    {
        outputs = def.get(".outputs");
    }
    catch (std::invalid_argument & e)
    {
        std::throw_with_nested(std::invalid_argument("Output builder expects definition to have a .outputs section."));
    }
    Op_t outputsStage = buildOutputStage(outputs);

    return Con_t(name->GetString(), parents,
                 [=](const Obs_t & input) -> Obs_t { return outputsStage(checkStage(input)); });
}

} // namespace builder::internals::builders
#endif // _BUILDERS_OUTPUT_H
