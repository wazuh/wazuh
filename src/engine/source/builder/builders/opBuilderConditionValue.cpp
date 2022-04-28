/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "opBuilderConditionValue.hpp"

#include <fmt/format.h>

namespace builder::internals::builders
{

base::Lifter opBuilderConditionValue(const base::DocumentValue &def,
                                      types::TracerFn tr)
{
    if (!def.MemberBegin()->name.IsString())
    {
        throw std::runtime_error("Error building condition value, key of "
                                 "definition must be a string.");
    }

    std::string field =
        json::formatJsonPath(def.MemberBegin()->name.GetString());

    // TODO: build document with value only
    base::Document doc {def};
    const std::string successTrace =
        fmt::format("{} Condition Success", doc.str());
    const std::string failureTrace =
        fmt::format("{} Condition Failure", doc.str());

    // Return Lifter
    return [=](base::Observable o)
    {
        // Append rxcpp operation
        return o.filter(
            [=](base::Event e)
            {
                if (e->getEvent()->equals(field, doc.begin()->value))
                {
                    tr(successTrace);
                    return true;
                }
                else
                {
                    tr(failureTrace);
                    return false;
                }
            });
    };
}

} // namespace builder::internals::builders
