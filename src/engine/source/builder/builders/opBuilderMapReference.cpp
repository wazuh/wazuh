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

types::Lifter opBuilderMapReference(const types::DocumentValue & def)
{
    // Make deep copy of value
    std::string field = "/" + string(def.MemberBegin()->name.GetString());
    std::string reference = def.MemberBegin()->value.GetString();
    reference = "/" + reference.substr(1, std::string::npos);

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
