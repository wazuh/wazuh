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
    if (!def.MemberBegin()->name.IsString())
    {
        throw std::runtime_error("Error building condition value, key of definition must be a string.");
    }

    std::string field = json::formatJsonPath(def.MemberBegin()->name.GetString());
    // TODO: build document with value only
    types::Document value{def};

    // Return Lifter
    return [=](types::Observable o)
    {
        // Append rxcpp operation
        return o.filter([=](types::Event e) {
            return e->equals(field, value.begin()->value);
        });
    };
}

} // namespace builder::internals::builders
