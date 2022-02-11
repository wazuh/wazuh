/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "opBuilderMap.hpp"

#include <glog/logging.h>
#include <stdexcept>
#include <string>

#include "registry.hpp"
#include "syntax.hpp"

using namespace std;

namespace builder::internals::builders
{

types::Lifter opBuilderMap(const types::DocumentValue & def)
{
    // Check that input is as expected and throw exception otherwise
    if (!def.IsObject())
    {
        auto msg = "map builder expects value to be an object, but got " + def.GetType();
        LOG(ERROR) << msg << endl;
        throw std::invalid_argument(msg);
    }
    if (def.GetObject().MemberCount() != 1)
    {
        auto msg = "map build expects value to have only one key, but got" + def.GetObject().MemberCount();
        LOG(ERROR) << msg << endl;
        throw std::invalid_argument(msg);
    }

    // Call apropiate builder depending on value
    auto v = def.MemberBegin();
    if (v->value.IsString())
    {
        string vStr = v->value.GetString();
        switch (vStr[0])
        {
            // TODO: handle that only allowed map helpers are built
            case syntax::FUNCTION_HELPER_ANCHOR:
                return std::get<types::OpBuilder>(Registry::getBuilder("helper." + vStr.substr(1, std::string::npos)))(
                    def);
                break;
            case syntax::REFERENCE_ANCHOR:
                return std::get<types::OpBuilder>(Registry::getBuilder("map.reference"))(def);
                break;
            default:
                return std::get<types::OpBuilder>(Registry::getBuilder("map.value"))(def);
        }
    }
    else if (v->value.IsArray())
    {
        return std::get<types::OpBuilder>(Registry::getBuilder("map.array"))(def);
    }
    else if (v->value.IsObject())
    {
        return std::get<types::OpBuilder>(Registry::getBuilder("map.object"))(def);
    }
    else
    {
        return std::get<types::OpBuilder>(Registry::getBuilder("map.value"))(def);
    }
}

} // namespace builder::internals::builders
