/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "baseHelper.hpp"

#include <algorithm>
#include <optional>
#include <sstream>
#include <variant>

#include <fmt/format.h>

#include "baseTypes.hpp"
#include "syntax.hpp"

namespace helper::base
{

std::tuple<std::string, std::string, std::vector<std::string>>
extractDefinition(const std::any& definition)
{
    std::tuple<std::string, std::string, std::vector<std::string>> extracted;
    try
    {
        extracted =
            std::any_cast<std::tuple<std::string, std::string, std::vector<std::string>>>(
                definition);
    }
    catch (const std::bad_any_cast& e)
    {
        std::throw_with_nested(std::runtime_error(
            fmt::format("Engine helpers: Can not process definition: {}", e.what())));
    }

    return extracted;
}

std::vector<Parameter> processParameters(const std::string name,
                                         const std::vector<std::string>& parameters)
{
    std::vector<Parameter> newParameters;
    std::transform(parameters.begin(),
                   parameters.end(),
                   std::back_inserter(newParameters),
                   [name](const std::string& parameter) -> Parameter
                   {
                       if (builder::internals::syntax::REFERENCE_ANCHOR == parameter[0])
                       {
                           std::string pointerPath;
                           try
                           {
                               pointerPath =
                                   json::Json::formatJsonPath(parameter.substr(1));
                           }
                           catch (const std::exception& e)
                           {
                               std::throw_with_nested(std::runtime_error(fmt::format(
                                   "Engine helpers: \"{}\" function: Can not format "
                                   "parameter \"{}\" to Json pointer path: {}",
                                   name,
                                   parameter,
                                   e.what())));
                           }
                           return {Parameter::Type::REFERENCE, pointerPath};
                       }
                       else
                       {
                           return {Parameter::Type::VALUE, parameter};
                       }
                   });

    return newParameters;
}

void checkParametersSize(const std::string name,
                         const std::vector<Parameter>& parameters,
                         size_t size)
{
    if (parameters.size() != size)
    {
        throw std::runtime_error(fmt::format(
            "Engine helpers: \"{}\" function: Expected {} parameters but got {}.",
            name,
            size,
            parameters.size()));
    }
}

void checkParametersMinSize(const std::string name,
                            const std::vector<Parameter>& parameters,
                            const size_t minSize)
{
    if (parameters.size() < minSize)
    {
        throw std::runtime_error(fmt::format("Engine helpers: \"{}\" function: Expected "
                                             "at least {} parameters but got {}.",
                                             name,
                                             minSize,
                                             parameters.size()));
    }
}

void checkParameterType(const std::string name,
                        const Parameter& parameter,
                        Parameter::Type type)
{
    if (parameter.m_type != type)
    {
        throw std::runtime_error(
            fmt::format("Engine helpers: \"{}\" function: Parameter \"{}\" is of type "
                        "\"{}\" but it is expected to be of type \"{}\".",
                        name,
                        parameter.m_value,
                        static_cast<int>(parameter.m_type),
                        static_cast<int>(type)));
    }
}

std::string formatHelperName(const std::string& name,
                             const std::string& targetField,
                             const std::vector<Parameter>& parameters)
{
    std::stringstream formattedName;
    formattedName << fmt::format("helper.{}[{}", name, targetField);
    if (parameters.size() > 0)
    {
        formattedName << fmt::format(", {}", parameters.begin()->m_value);
        for (auto it = parameters.begin() + 1; it != parameters.end(); ++it)
        {
            formattedName << fmt::format(", {}", it->m_value);
        }
    }
    formattedName << "]";

    return formattedName.str();
}
} // namespace helper::base
