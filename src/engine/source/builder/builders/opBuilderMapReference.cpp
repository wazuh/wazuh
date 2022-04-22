/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "opBuilderMapReference.hpp"

#include <string>

#include <fmt/format.h>

using namespace std;

namespace builder::internals::builders
{

// TODO Add test for this
base::Lifter opBuilderMapReference(const base::DocumentValue &def,
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

    // Debug trace
    base::Document value{def};
    std::string successTrace = fmt::format("{} Mapping Success", value.str());
    std::string failureTrace = fmt::format("{} Mapping Failure", value.str());

    // Return Lifter
    return [=](base::Observable o)
    {
        // Append rxcpp operation
        return o.map(
            [=](base::Event e)
            {
                e->getEvent()->set(field, reference);
                tr(successTrace);
                return e;
            });
    };
}

} // namespace builder::internals::builders
