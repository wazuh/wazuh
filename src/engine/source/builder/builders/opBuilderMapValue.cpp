/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "opBuilderMapValue.hpp"

namespace builder::internals::builders
{
// TODOL DOC and test this
base::Lifter opBuilderMapValue(const base::DocumentValue& def,
                               types::TracerFn tr)
{
    // Make deep copy of value
    std::string field =
        json::formatJsonPath(def.MemberBegin()->name.GetString());

    base::Document doc {def};
    std::string defstr {doc.str()};
    // Debug trace
    const std::string successTrace =
        fmt::format("{} Mapping Success", doc.str());
    const std::string failureTrace =
        fmt::format("{} Mapping Failure", doc.str());

    // Return Lifter
    return [=](base::Observable o)
    {
        // Append rxcpp operation
        return o.map(
            [=](base::Event e)
            {
                e->getEvent()->set(field, doc.m_doc.MemberBegin()->value)
                    ? tr(successTrace)
                    : tr(failureTrace);
                return e;
            });
    };
}

} // namespace builder::internals::builders
