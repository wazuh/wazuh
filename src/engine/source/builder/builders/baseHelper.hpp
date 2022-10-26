/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _BASE_HELPER_H
#define _BASE_HELPER_H

#include <any>
#include <string>
#include <tuple>
#include <vector>

namespace helper::base
{

/**
 * @brief Struct to handle that parameters may be a value or a reference.
 *
 */
struct Parameter
{
    enum class Type
    {
        REFERENCE,
        VALUE
    };

    Type m_type;
    std::string m_value;

    friend std::ostream& operator<<(std::ostream& os, const Parameter& parameter)
    {
        os << parameter.m_value;
        return os;
    }
};

/**
 * @brief Extract expected parameters from std::any.
 *  <string helperName> <string targetField> <array of string parameters>
 * targetField must be a valid JSON pointer path.
 * References inside parameters must be preceded by ANCHOR_REFERENCE.
 * /envent/original: name ["param1", ... ]
 *
 * @param definition
 * @return std::tuple<std::string, std::string, std::vector<std::string>>
 *
 * @throws std::runtime_error if definition is not a tuple with the expected structure.
 */
std::tuple<std::string, std::string, std::vector<std::string>>
extractDefinition(const std::any& definition);

/**
 * @brief Transforms a vector of strings into a vector of Parameters.
 * If the string is a reference, it will be transformed into a Parameter with
 * Type::REFERENCE and the reference will be transformed into a JSON pointer path.
 *
 * If the string is a value, it will be transformed into a Parameter with Type::VALUE.
 *
 * @param parameters vector of strings
 * @return std::vector<Parameter>
 *
 * @throws std::runtime_error if a reference parameter cannot be transformed into a JSON
 * pointer path.
 */
std::vector<Parameter> processParameters(const std::string name,
                                         const std::vector<std::string>& parameters);

/**
 * @brief Check that the number of parameters is correct and throw otherwise.
 *
 * @param parameters
 * @param size
 *
 * @throws std::runtime_error if the number of parameters is not correct.
 */
void checkParametersSize(const std::string name,
                         const std::vector<Parameter>& parameters,
                         size_t size);

/**
 * @brief Check that the number of parameters is equal or bigger than
 * minimum and throw otherwise.
 *
 * @param parameters vector of parameters to check
 * @param size minimum size of parameters
 *
 * @throws std::runtime_error if the number of parameters is not correct.
 */
void checkParametersMinSize(const std::string name,
                            const std::vector<Parameter>& parameters,
                            const size_t min_size);
/**
 * @brief Check that the paremeter is of Parameter::Type and throw otherwise.
 *
 * @param parameter
 * @param type
 *
 * @throws std::runtime_error if the parameter is not of the expected type.
 */
void checkParameterType(const std::string name,
                        const Parameter& parameter,
                        Parameter::Type type);

/**
 * @brief Format the name to be used in Tracers.
 * Format: "helper.<name>[<targetField>/<parameters>]"
 *
 * @param targetField
 * @param name
 * @param parameters
 * @return std::string
 */
std::string formatHelperName(const std::string& targetField,
                             const std::string& name,
                             const std::vector<Parameter>& parameters);

} // namespace helper::base

#endif // _BASE_HELPER_H
