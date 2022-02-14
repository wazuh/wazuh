/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "stageBuilderOutputs.hpp"

#include <glog/logging.h>
#include <stdexcept>
#include <string>
#include <vector>

#include "registry.hpp"

using namespace std;

namespace builder::internals::builders
{

types::Lifter stageBuilderOutputs(const types::DocumentValue & def)
{
    // Assert value is as expected
    if (!def.IsArray())
    {
        string msg = "Stage outputs builder, expected array but got " + def.GetType();
        LOG(ERROR) << msg << endl;
        throw invalid_argument(msg);
    }

    // Build all outputs
    vector<types::Lifter> outputs;
    for (auto it = def.Begin(); it != def.End(); ++it)
    {
        try
        {
            outputs.push_back(get<types::OpBuilder>(Registry::getBuilder(it->MemberBegin()->name.GetString()))(it->MemberBegin()->value));
        }
        catch (std::exception & e)
        {
            string msg = "Stage outputs builder encountered exception on building.";
            LOG(ERROR) << msg << " From exception: " << e.what() << endl;
            std::throw_with_nested(runtime_error(msg));
        }
    }

    // Broadcast to all operations
    types::Lifter output;
    try
    {
        output = get<types::CombinatorBuilder>(Registry::getBuilder("combinator.broadcast"))(outputs);
    }
    catch (std::exception & e)
    {
        string msg = "Stage outputs builder encountered exception broadcasting all outputs.";
        LOG(ERROR) << msg << " From exception: " << e.what() << endl;
        std::throw_with_nested(runtime_error(msg));
    }

    // Finally return Lifter
    return output;
}

} // namespace builder::internals::builders
