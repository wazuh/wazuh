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

#include "syntax.hpp"

namespace builder::internals::builders
{

types::Lifter opBuilderConditionReference(const types::DocumentValue & def)
{
    // Estract field and reference
    // TODO Add test for this
    std::string field {json::Document::preparePath(def.MemberBegin()->name.GetString())};

    if (!def.MemberBegin()->value.IsString())
    {
        throw std::runtime_error("The value of the field '" + field + "' must be a string.");
    }
    std::string reference {def.MemberBegin()->value.GetString()};
    // TODO: Delete the `$` at the beginning of the reference (Adds test, doc and handle the invalid reference)
    reference = json::Document::preparePath(reference.substr(1, std::string::npos));

    // Return Lifter
    return [=](types::Observable o)
    {
        // Append rxcpp operation
        return o.filter(
            [=](types::Event e)
            {
                // TODO: implemente proper json check reference
                // TODO: remove try and catch
                try
                {
                    auto v = e->get(reference);
                    return v != nullptr && e->check(field, v);
                }
                catch (std::exception & ex)
                {
                    return false;
                }
            });
    };
}

} // namespace builder::internals::builders
