/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "opBuilderCondition.hpp"

#include <stdexcept>
#include <string>

#include "registry.hpp"
#include "syntax.hpp"

#include <logging/logging.hpp>

namespace builder::internals::builders
{

types::Lifter opBuilderCondition(const types::DocumentValue & def, types::TracerFn tr)
{
    // Check that input is as expected and throw exception otherwise
    if (!def.IsObject())
    {
        auto msg = fmt::format("Expexted type 'Object' but got [{}]", def.GetType());
        WAZUH_LOG_ERROR("{}", msg);
        throw std::invalid_argument(std::move(msg));
    }
    if (def.GetObject().MemberCount() != 1)
    {
        auto msg = fmt::format("Expected single key but got: [{}]", def.GetObject().MemberCount());
        WAZUH_LOG_ERROR("{}", msg);
        throw std::invalid_argument(std::move(msg));
    }

    // Call apropiate builder depending on value
    auto v = def.MemberBegin();
    if (v->value.IsString())
    {
        std::string vStr = v->value.GetString();
        switch (vStr[0])
        {
            case syntax::FUNCTION_HELPER_ANCHOR:
                return std::get<types::OpBuilder>(Registry::getBuilder("helper." + vStr.substr(1, vStr.find("/") - 1)))(
                    def, tr);
                break;
            case syntax::REFERENCE_ANCHOR:
                return std::get<types::OpBuilder>(Registry::getBuilder("condition.reference"))(def, tr);
                break;
            default:
                return std::get<types::OpBuilder>(Registry::getBuilder("condition.value"))(def, tr);
        }
    }
    else if (v->value.IsArray())
    {
        return std::get<types::OpBuilder>(Registry::getBuilder("condition.array"))(def, tr);
    }
    else if (v->value.IsObject())
    {
        return std::get<types::OpBuilder>(Registry::getBuilder("condition.object"))(def, tr);
    }
    else
    {
        return std::get<types::OpBuilder>(Registry::getBuilder("condition.value"))(def, tr);
    }
}

} // namespace builder::internals::builders
