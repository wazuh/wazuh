
#include <any>
#include <gtest/gtest.h>
#include <vector>

#include <baseTypes.hpp>

#include "baseHelper.hpp"

using namespace base;

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
