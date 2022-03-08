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

using namespace std;

namespace builder::internals::builders
{

// TODO Add test for this
types::Lifter opBuilderMapReference(const types::DocumentValue & def)
{
    // Make deep copy of value
    std::string field {json::Document::preparePath((def.MemberBegin()->name.GetString()))};
    if (!def.MemberBegin()->value.IsString())
    {
        throw std::runtime_error("The value of the field '" + field + "' must be a string.");
    }
    std::string reference {def.MemberBegin()->value.GetString()};
    // TODO Should start with a `$` to reference a field (Adds test, doc and handle the invalid reference)
    reference = json::Document::preparePath(reference.substr(1, std::string::npos));

    // Return Lifter
    return [=](types::Observable o)
    {
        // Append rxcpp operation
        return o.map(
            [=](types::Event e)
            {
                auto v = e->get(reference);
                e->set(field, *v);
                return e;
            });
    };
}

} // namespace builder::internals::builders
