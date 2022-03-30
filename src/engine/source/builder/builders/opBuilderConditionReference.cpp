/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "opBuilderConditionReference.hpp"

#include <algorithm>
#include <string>

#include <fmt/format.h>

#include "syntax.hpp"

namespace builder::internals::builders
{

types::Lifter opBuilderConditionReference(const types::DocumentValue &def,
                                          types::TracerFn tr)
{
    if (!def.MemberBegin()->name.IsString())
    {
        throw std::runtime_error("Error building condition reference, key of "
                                 "definition must be a string.");
    }
    if (!def.MemberBegin()->value.IsString())
    {
        throw std::runtime_error("Error building condition reference, value of "
                                 "definition must be a string.");
    }

    // Estract and prepare field and reference
    std::string field {
        json::formatJsonPath(def.MemberBegin()->name.GetString())};
    std::string reference {def.MemberBegin()->value.GetString()};
    if (reference.front() == '$')
    {
        reference.erase(0, 1);
    }
    reference = json::formatJsonPath(reference);
    std::string successTrace =
        fmt::format("{{{}: {}}} Condition Success",
                    def.MemberBegin()->name.GetString(),
                    def.MemberBegin()->value.GetString());
    std::string failureTrace =
        fmt::format("{{{}: {}}} Condition Failure",
                    def.MemberBegin()->name.GetString(),
                    def.MemberBegin()->value.GetString());

    // Return Lifter
    return [=](types::Observable o)
    {
        // Append rxcpp operation
        return o.filter(
            [=](types::Event e)
            {
                if (e->equals(field, reference))
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
