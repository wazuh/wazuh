/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "opBuilderConditionValue.hpp"

using namespace std;

namespace builder::internals::builders
{

types::Lifter opBuilderConditionValue(const types::DocumentValue & def)
{
    // Make deep copy of value
    types::Document doc{def};

    // Return Lifter
    return [=](types::Observable o)
    {
        // Append rxcpp operation
        return o.filter([=](types::Event e) { return e->check(doc); });
    };
}

} // namespace builder::internals::builders
