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
    std::string field = def.MemberBegin()->name.GetString();
    std::string reference = def.MemberBegin()->value.GetString();
    reference = reference.substr(1, std::string::npos);

    // Return Lifter
    return [=](types::Observable o)
    {
        // Append rxcpp operation
        return o.filter(
            [=](types::Event e)
            {
                //TODO: implemente proper json check reference
                auto v = e->get("/" + reference);
                return e->check("/" + field, v);
            });
    };
}

} // namespace builder::internals::builders
