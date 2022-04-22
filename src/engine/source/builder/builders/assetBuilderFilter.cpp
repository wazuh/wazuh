/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "assetBuilderFilter.hpp"

#include <map>
#include <stdexcept>
#include <string>
#include <vector>

#include "registry.hpp"

#include <logging/logging.hpp>
#include <fmt/format.h>

namespace builder::internals::builders
{

types::ConnectableT assetBuilderFilter(const base::Document & def)
{
    // Assert document is as expected
    if (!def.m_doc.IsObject())
    {
        auto msg = fmt::format("Filter builder expects value to be an object, but got [{}]", def.m_doc.GetType());
        WAZUH_LOG_ERROR("{}", msg);
        throw std::invalid_argument(msg);
    }

    std::vector<base::Lifter> stages;

    // Needed to build stages in a for loop popping its attributes
    std::map<std::string, const base::DocumentValue &> attributes;
    try
    {
        for (auto it = def.m_doc.MemberBegin(); it != def.m_doc.MemberEnd(); ++it)
        {
            attributes.emplace(it->name.GetString(), it->value);
        }
    }
    catch (std::exception & e)
    {
        const char* msg = "Filter builder encountered exception in building auxiliary map.";
        WAZUH_LOG_ERROR("{} From exception: [{}]", msg, e.what());
        std::throw_with_nested(std::runtime_error(msg));
    }

    // Attribute name
    std::string name;
    try
    {
        name = attributes.at("name").GetString();
        attributes.erase("name");
    }
    catch (std::exception & e)
    {
        const char* msg = "Filter builder encountered exception building attribute name.";
        WAZUH_LOG_ERROR("{} From exception: [{}]", msg, e.what());
        std::throw_with_nested(std::invalid_argument(msg));
    }

    // Attribute after
    std::vector<std::string> after;
    try
    {
        for (const base::DocumentValue & parentName : attributes.at("after").GetArray())
        {
            after.push_back(parentName.GetString());
        }
        attributes.erase("after");
    }
    catch (std::exception & e)
    {
        const char* msg = "Filter builder encountered exception building attribute after.";
        WAZUH_LOG_ERROR("{} From exception: [{}]", msg, e.what());
        std::throw_with_nested(std::invalid_argument(msg));
    }

    // Create tracer
    types::ConnectableT::Tracer tr{name};

    // Stage allow
    try
    {
        stages.push_back(std::get<types::OpBuilder>(Registry::getBuilder("allow"))(attributes.at("allow"), tr.tracerLogger()));
        attributes.erase("allow");
    }
    catch (std::exception & e)
    {
        const char* msg = "Filter builder encountered exception building stage allow.";
        WAZUH_LOG_ERROR("{} From exception: [{}]", msg, e.what());
        std::throw_with_nested(std::runtime_error(msg));
    }

    // Rest of stages
    std::vector<std::string> toPop;
    for (auto it = attributes.begin(); it != attributes.end(); ++it)
    {
        try
        {
            stages.push_back(std::get<types::OpBuilder>(Registry::getBuilder(it->first))(it->second, tr.tracerLogger()));
            toPop.push_back(it->first);
        }
        catch (std::exception & e)
        {
            auto msg = fmt::format(
                "Filter builder encountered exception building stage [{}].",
                it->first);
            WAZUH_LOG_ERROR("{} From exception: [{}]", msg, e.what());
            std::throw_with_nested(std::runtime_error(msg));
        }
    }

    // Check no strange attributes are left
    for (auto name : toPop)
    {
        attributes.erase(name);
    }
    if (!attributes.empty())
    {
        const char* msg = "Filter builder, json definition contains unproccessed attributes";
        WAZUH_LOG_ERROR("{}", msg);
        throw std::invalid_argument(msg);
    }

    // Combine all stages
    try
    {
        base::Lifter filter = std::get<types::CombinatorBuilder>(
            Registry::getBuilder("combinator.chain"))(stages);

        return types::ConnectableT {name, after, filter, tr};
    }
    catch (std::exception & e)
    {
        const char* msg = "Filter builder encountered exception building chaining all stages.";
        WAZUH_LOG_ERROR("{} From exception: [{}]", msg, e.what());
        std::throw_with_nested(std::runtime_error(msg));
    }

}

} // namespace builder::internals::builders
