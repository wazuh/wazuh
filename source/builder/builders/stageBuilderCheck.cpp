/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "stageBuilderCheck.hpp"

#include <glog/logging.h>
#include <stdexcept>
#include <string>
#include <vector>

#include "registry.hpp"

using namespace std;

namespace builder::internals::builders
{

types::Lifter stageBuilderCheck(const types::DocumentValue & def)
{
    // Assert value is as expected
    if (!def.IsArray())
    {
        string msg = "Stage check builder, expected array but got " + def.GetType();
        LOG(ERROR) << msg << endl;
        throw invalid_argument(msg);
    }

    // Build all conditions
    vector<types::Lifter> conditions;
    for (auto it = def.Begin(); it != def.End(); ++it)
    {
        try
        {
            conditions.push_back(get<types::OpBuilder>(Registry::getBuilder("condition"))(*it));
        }
        catch (std::exception & e)
        {
            string msg = "Stage check builder encountered exception on building.";
            LOG(ERROR) << msg << " From exception: " << e.what() << endl;
            std::throw_with_nested(runtime_error(msg));
        }
    }

    // Chain all operations
    types::Lifter check;
    try
    {
        check = get<types::CombinatorBuilder>(Registry::getBuilder("combinator.chain"))(conditions);
    }
    catch (std::exception & e)
    {
        string msg = "Stage check builder encountered exception chaining all conditions.";
        LOG(ERROR) << msg << " From exception: " << e.what() << endl;
        std::throw_with_nested(runtime_error(msg));
    }

    // Finally return Lifter
    return check;
}

} // namespace builder::internals::builders
