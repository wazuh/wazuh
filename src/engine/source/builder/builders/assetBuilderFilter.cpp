/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "assetBuilderFilter.hpp"

#include <glog/logging.h>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

#include "registry.hpp"

using namespace std;

namespace builder::internals::builders
{

types::ConnectableT assetBuilderFilter(const types::Document & def)
{
    // Assert document is as expected
    if (!def.m_doc.IsObject())
    {
        auto msg = "Filter builder expects value to be an object, but got " + def.m_doc.GetType();
        LOG(ERROR) << msg << endl;
        throw std::invalid_argument(msg);
    }

    vector<types::Lifter> stages;

    // Needed to build stages in a for loop popping its attributes
    map<string, const types::DocumentValue &> attributes;
    try
    {
        for (auto it = def.m_doc.MemberBegin(); it != def.m_doc.MemberEnd(); ++it)
        {
            attributes.emplace(it->name.GetString(), it->value);
        }
    }
    catch (std::exception & e)
    {
        string msg = "Filter builder encountered exception in building auxiliary map.";
        LOG(ERROR) << msg << " From exception: " << e.what() << endl;
        std::throw_with_nested(runtime_error(msg));
    }

    // Attribute name
    string name;
    try
    {
        name = attributes.at("name").GetString();
        attributes.erase("name");
    }
    catch (std::exception & e)
    {
        string msg = "Filter builder encountered exception building attribute name.";
        LOG(ERROR) << msg << " From exception: " << e.what() << endl;
        std::throw_with_nested(invalid_argument(msg));
    }

    // Attribute after
    vector<string> after;
    try
    {
        for (const types::DocumentValue & parentName : attributes.at("after").GetArray())
        {
            after.push_back(parentName.GetString());
        }
        attributes.erase("after");
    }
    catch (std::exception & e)
    {
        string msg = "Filter builder encountered exception building attribute after.";
        LOG(ERROR) << msg << " From exception: " << e.what() << endl;
        std::throw_with_nested(invalid_argument(msg));
    }

    // Stage allow
    try
    {
        stages.push_back(get<types::OpBuilder>(Registry::getBuilder("allow"))(attributes.at("allow")));
        attributes.erase("allow");
    }
    catch (std::exception & e)
    {
        string msg = "Filter builder encountered exception building stage allow.";
        LOG(ERROR) << msg << " From exception: " << e.what() << endl;
        std::throw_with_nested(runtime_error(msg));
    }

    // Rest of stages
    std::vector<std::string> toPop;
    for (auto it = attributes.begin(); it != attributes.end(); ++it)
    {
        try
        {
            stages.push_back(get<types::OpBuilder>(Registry::getBuilder(it->first))(it->second));
            toPop.push_back(it->first);
        }
        catch (std::exception & e)
        {
            string msg = "Filter builder encountered exception building stage " + it->first + ".";
            LOG(ERROR) << msg << " From exception: " << e.what() << endl;
            std::throw_with_nested(runtime_error(msg));
        }
    }

    // Check no strange attributes are left
    for (auto name : toPop)
    {
        attributes.erase(name);
    }
    if (!attributes.empty())
    {
        string msg = "Filter builder, json definition contains unproccessed attributes";
        LOG(ERROR) << msg << endl;
        throw invalid_argument(msg);
    }

    // Combine all stages
    types::Lifter filter;
    try
    {
        filter = get<types::CombinatorBuilder>(Registry::getBuilder("combinator.chain"))(stages);
    }
    catch (std::exception & e)
    {
        string msg = "Filter builder encountered exception building chaining all stages.";
        LOG(ERROR) << msg << " From exception: " << e.what() << endl;
        std::throw_with_nested(runtime_error(msg));
    }

    // Finally return connectable
    return types::ConnectableT{name, after, filter};
}

} // namespace builder::internals::builders
