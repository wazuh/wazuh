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
// TODOL DOC and test this
base::Lifter opBuilderMapValue(const base::DocumentValue &def,
                                types::TracerFn tr)
{
    // Make deep copy of value
    base::Document doc {def};
    std::string field =
        json::formatJsonPath(def.MemberBegin()->name.GetString());
    std::string defstr {doc.str()};

    // Debug trace
    std::string successTrace = fmt::format("{} Mapping Success", doc.str());
    std::string failureTrace = fmt::format("{} Mapping Failure", doc.str());

    // Return Lifter
    return [=](base::Observable o)
    {
        // Append rxcpp operation
        return o.map(
            [=](base::Event e)
            {
                e->getEvent()->set(field, doc.m_doc.MemberBegin()->value);
                tr(successTrace);
                return e;
            });
    };
}

} // namespace builder::internals::builders
