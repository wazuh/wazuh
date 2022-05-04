/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "opBuilderCondition.hpp"

#include <functional>
#include <stdexcept>
#include <string>

#include "registry.hpp"
#include "syntax.hpp"

#include <logging/logging.hpp>

namespace builder::internals::builders
{
std::function<bool(types::Event)>
middleBuilderConditionReference(const types::DocumentValue& def,
                                types::TracerFn tr)
{
    if (!def.MemberBegin()->name.IsString())
    {
        throw std::runtime_error("Error building condition reference, key of "
                                 "definition must be a string.");
    }
    if (!def.MemberBegin()->value.IsString())
    {
        throw std::runtime_error("Error building condition reference, value of "
                                 "definition must be a string.");
    }

    // Estract and prepare field and reference
    std::string field {
        json::formatJsonPath(def.MemberBegin()->name.GetString())};
    std::string reference {def.MemberBegin()->value.GetString()};
    if (reference.front() == '$')
    {
        reference.erase(0, 1);
    }
    reference = json::formatJsonPath(reference);
    std::string successTrace =
        fmt::format("{{{}: {}}} Condition Success",
                    def.MemberBegin()->name.GetString(),
                    def.MemberBegin()->value.GetString());
    std::string failureTrace =
        fmt::format("{{{}: {}}} Condition Failure",
                    def.MemberBegin()->name.GetString(),
                    def.MemberBegin()->value.GetString());

    return [=](types::Event e)
    {
        if (e->equals(field, reference))
        {
            tr(successTrace);
            return true;
        }
        else
        {
            tr(failureTrace);
            return false;
        }
    };
}

std::function<bool(types::Event)>
middleBuilderConditionValue(const types::DocumentValue& def, types::TracerFn tr)
{
    if (!def.MemberBegin()->name.IsString())
    {
        throw std::runtime_error("Error building condition value, key of "
                                 "definition must be a string.");
    }

    std::string field =
        json::formatJsonPath(def.MemberBegin()->name.GetString());
    // TODO: build document with value only
    types::Document value {def};
    std::string successTrace = fmt::format("{} Condition Success", value.str());
    std::string failureTrace = fmt::format("{} Condition Failure", value.str());

    return [=](types::Event e)
    {
        if (e->equals(field, value.begin()->value))
        {
            tr(successTrace);
            return true;
        }
        else
        {
            tr(failureTrace);
            return false;
        }
    };
}

std::function<bool(types::Event)>
middleBuilderCondition(const types::DocumentValue& def, types::TracerFn tr)
{
    // Check that input is as expected and throw exception otherwise
    if (!def.IsObject())
    {
        auto msg =
            fmt::format("Expexted type 'Object' but got [{}]", def.GetType());
        WAZUH_LOG_ERROR("{}", msg);
        throw std::invalid_argument(std::move(msg));
    }
    if (def.GetObject().MemberCount() != 1)
    {
        auto msg = fmt::format("Expected single key but got: [{}]",
                               def.GetObject().MemberCount());
        WAZUH_LOG_ERROR("{}", msg);
        throw std::invalid_argument(std::move(msg));
    }

    // Call apropiate builder depending on value
    auto v = def.MemberBegin();
    std::function<bool(types::Event)> fn;
    if (v->value.IsString())
    {
        std::string vStr = v->value.GetString();
        switch (vStr[0])
        {
            case syntax::FUNCTION_HELPER_ANCHOR:
            {
                auto helperName = vStr.substr(1, vStr.find("/") - 1);
                fn = std::get<types::MiddleBuilderCondition>(
                    Registry::getBuilder("middle.helper." + helperName))(def,
                                                                         tr);
            }

            break;
            case syntax::REFERENCE_ANCHOR:
                fn = middleBuilderConditionReference(def, tr);
                break;
            default: fn = middleBuilderConditionValue(def, tr);
        }
    }
    // Array and objects are treated as values currently
    else
    {
        fn = middleBuilderConditionValue(def, tr);
    }

    return fn;
}

types::Lifter opBuilderCondition(const types::DocumentValue& def,
                                 types::TracerFn tr)
{
    auto conditionFn = middleBuilderCondition(def, tr);
    return [=](types::Observable input)
    {
        return input.filter([=](types::Event event)
                            { return conditionFn(event); });
    };
}

} // namespace builder::internals::builders
