/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "opBuilderMapValue.hpp"

using namespace std;

namespace builder::internals::builders
{

types::Lifter opBuilderMapValue(const types::DocumentValue & def)
{
    // Make deep copy of value
    types::Document doc{def};

    // Return Lifter
    return [=](types::Observable o)
    {
        // Append rxcpp operation
        return o.map(
            [=](types::Event e)
            {
                e->set(doc);
                return e;
            });
    };
}

} // namespace builder::internals::builders
