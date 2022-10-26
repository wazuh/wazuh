/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <any>
#include <gtest/gtest.h>
#include <vector>

#include <baseTypes.hpp>

#include "baseHelper.hpp"

using namespace base;

// extractDefinition
TEST(extractDefinition, Builds)
{
    std::any definition = std::make_tuple(
        std::string {"/field"}, std::string {"i_eq"}, std::vector<std::string> {"10"});

    ASSERT_NO_THROW(helper::base::extractDefinition(definition));
}

TEST(extractDefinition, Exec_extract_definition_false)
{
    std::any definition = std::make_tuple(std::string {"/field2check"},
                                          std::string {"i_eq"},
                                          std::string {"i_ne"},
                                          std::vector<std::string> {"12"});

    ASSERT_THROW(helper::base::extractDefinition(definition), std::runtime_error);
}

TEST(extractDefinition, Exec_extract_definition_true)
{
    std::any definition = std::make_tuple(std::string {"/field2check"},
                                          std::string {"i_eq"},
                                          std::vector<std::string> {"12"});

    auto [targetField, name, raw_parameters] =
        helper::base::extractDefinition(definition);

    std::string field_str = targetField;
    std::string name_str = name;
    std::string parameters_str = raw_parameters[0];

    ASSERT_EQ(field_str, "/field2check");
    ASSERT_EQ(name_str, "i_eq");
    ASSERT_EQ(parameters_str, "12");
}

// processParameters
TEST(processParameters, Builds)
{
    std::vector<std::string> vector = {"10"};

    std::vector<helper::base::Parameter> parameters =
        helper::base::processParameters("processParameters", vector);

    ASSERT_NO_THROW(helper::base::processParameters("processParameters", vector));
}

TEST(processParameters, Exec_extract_definition_value_true)
{
    std::vector<std::string> vector = {"10"};

    std::vector<helper::base::Parameter> parameters =
        helper::base::processParameters("processParameters", vector);

    ASSERT_EQ(parameters[0].m_type, helper::base::Parameter::Type::VALUE);
    ASSERT_EQ(parameters[0].m_value, "10");
}

TEST(processParameters, Exec_extract_definition_reference_true)
{
    std::vector<std::string> vector = {"$test"};

    std::vector<helper::base::Parameter> parameters =
        helper::base::processParameters("processParameters", vector);

    ASSERT_EQ(parameters[0].m_type, helper::base::Parameter::Type::REFERENCE);
    ASSERT_EQ(parameters[0].m_value, "/test");
}

// checkParametersSize
TEST(checkParametersSize, Builds)
{
    helper::base::Parameter p;
    p.m_value = "10";
    p.m_type = helper::base::Parameter::Type::VALUE;

    std::vector<helper::base::Parameter> parameters = {p};

    ASSERT_NO_THROW(
        helper::base::checkParametersSize("checkParameterType", parameters, 1));
}

TEST(checkParametersSize, Exec_check_parameters_size_false)
{
    helper::base::Parameter p;
    p.m_value = "10";
    p.m_type = helper::base::Parameter::Type::VALUE;

    std::vector<helper::base::Parameter> parameters = {p};

    ASSERT_THROW(helper::base::checkParametersSize("checkParameterType", parameters, 2),
                 std::runtime_error);
}

TEST(checkParametersSize, Exec_check_parameters_size_true)
{
    helper::base::Parameter p;
    p.m_value = "$test";
    p.m_type = helper::base::Parameter::Type::REFERENCE;

    std::vector<helper::base::Parameter> parameters = {p};

    ASSERT_NO_THROW(
        helper::base::checkParametersSize("checkParameterType", parameters, 1));
}

// checkParameterType
TEST(checkParameterType, Builds)
{
    helper::base::Parameter p;
    p.m_value = "10";
    p.m_type = helper::base::Parameter::Type::VALUE;

    std::vector<helper::base::Parameter> parameters = {p};

    ASSERT_NO_THROW(helper::base::checkParameterType(
        "checkParameterType", parameters[0], helper::base::Parameter::Type::VALUE));
}

TEST(checkParameterType, Exec_check_parameters_type_false)
{
    helper::base::Parameter p;
    p.m_value = "10";
    p.m_type = helper::base::Parameter::Type::VALUE;

    std::vector<helper::base::Parameter> parameters = {p};

    ASSERT_THROW(
        helper::base::checkParameterType("checkParameterType",
                                         parameters[0],
                                         helper::base::Parameter::Type::REFERENCE),
        std::runtime_error);
}

TEST(checkParameterType, Exec_check_parameters_type_value_true)
{
    helper::base::Parameter p;
    p.m_value = "10";
    p.m_type = helper::base::Parameter::Type::VALUE;

    std::vector<helper::base::Parameter> parameters = {p};

    ASSERT_NO_THROW(helper::base::checkParameterType(
        "checkParameterType", parameters[0], helper::base::Parameter::Type::VALUE));
}

TEST(checkParameterType, Exec_check_parameters_type_reference_true)
{
    helper::base::Parameter p;
    p.m_value = "10";
    p.m_type = helper::base::Parameter::Type::REFERENCE;

    std::vector<helper::base::Parameter> parameters = {p};

    ASSERT_NO_THROW(helper::base::checkParameterType(
        "checkParameterType", parameters[0], helper::base::Parameter::Type::REFERENCE));
}

// formatHelperName
TEST(formatHelperName, Builds)
{
    const std::string name = "test_helper";
    const std::string targetField = "/test";

    helper::base::Parameter p;
    p.m_value = "10";
    p.m_type = helper::base::Parameter::Type::VALUE;

    std::vector<helper::base::Parameter> parameters = {p};

    ASSERT_NO_THROW(helper::base::formatHelperName(name, targetField, parameters));
}

TEST(formatHelperName, Exec_format_helper_filter_name_true)
{
    const std::string name = "test_helper";
    const std::string targetField = "/test";

    helper::base::Parameter p;
    p.m_value = "10";
    p.m_type = helper::base::Parameter::Type::VALUE;

    std::vector<helper::base::Parameter> parameters = {p};

    std::string result = helper::base::formatHelperName(name, targetField, parameters);

    ASSERT_EQ(result, "helper.test_helper[/test, 10]");
}
