
#include <any>
#include <gtest/gtest.h>
#include <vector>

#include <baseTypes.hpp>
#include <defs/mocks/failDef.hpp>
#include <defs/mocks/singleDef.hpp>

#include "baseHelper.hpp"

using namespace base;
using namespace helper::base;
using namespace defs::mocks;
class ProcessParamTest : public ::testing::TestWithParam<std::tuple<std::vector<std::string>, std::vector<Parameter>>>
{
public:
    std::shared_ptr<defs::IDefinitions> m_definitions = std::make_shared<SingleDef>();
    std::string m_name = "test_helper_name";
};

TEST_P(ProcessParamTest, Builds)
{
    auto [rawParameters, expected] = GetParam();

    auto parameters = processParameters(m_name, rawParameters, m_definitions);
    ASSERT_EQ(parameters, expected);
}

INSTANTIATE_TEST_SUITE_P(
    Builds,
    ProcessParamTest,
    ::testing::Values(
        std::make_tuple<std::vector<std::string>, std::vector<Parameter>>({"10"}, {{Parameter::Type::VALUE, "10"}}),
        std::make_tuple<std::vector<std::string>, std::vector<Parameter>>({"$ref"},
                                                                          {{Parameter::Type::REFERENCE, "/ref"}}),
        std::make_tuple<std::vector<std::string>, std::vector<Parameter>>(
            {SingleDef::referenceName()}, {{Parameter::Type::VALUE, SingleDef::strValue()}}),
        std::make_tuple<std::vector<std::string>, std::vector<Parameter>>({"10", "$ref", SingleDef::referenceName()},
                                                                          {{Parameter::Type::VALUE, "10"},
                                                                           {Parameter::Type::REFERENCE, "/ref"},
                                                                           {Parameter::Type::VALUE,
                                                                            SingleDef::strValue()}})));

// checkParametersSize
TEST(checkParametersSize, Builds)
{
    helper::base::Parameter p;
    p.m_value = "10";
    p.m_type = helper::base::Parameter::Type::VALUE;

    std::vector<helper::base::Parameter> parameters = {p};

    ASSERT_NO_THROW(helper::base::checkParametersSize("checkParameterType", parameters, 1));
}

TEST(checkParametersSize, Exec_check_parameters_size_false)
{
    helper::base::Parameter p;
    p.m_value = "10";
    p.m_type = helper::base::Parameter::Type::VALUE;

    std::vector<helper::base::Parameter> parameters = {p};

    ASSERT_THROW(helper::base::checkParametersSize("checkParameterType", parameters, 2), std::runtime_error);
}

TEST(checkParametersSize, Exec_check_parameters_size_true)
{
    helper::base::Parameter p;
    p.m_value = "$test";
    p.m_type = helper::base::Parameter::Type::REFERENCE;

    std::vector<helper::base::Parameter> parameters = {p};

    ASSERT_NO_THROW(helper::base::checkParametersSize("checkParameterType", parameters, 1));
}

// checkParameterType
TEST(checkParameterType, Builds)
{
    helper::base::Parameter p;
    p.m_value = "10";
    p.m_type = helper::base::Parameter::Type::VALUE;

    std::vector<helper::base::Parameter> parameters = {p};

    ASSERT_NO_THROW(
        helper::base::checkParameterType("checkParameterType", parameters[0], helper::base::Parameter::Type::VALUE));
}

TEST(checkParameterType, Exec_check_parameters_type_false)
{
    helper::base::Parameter p;
    p.m_value = "10";
    p.m_type = helper::base::Parameter::Type::VALUE;

    std::vector<helper::base::Parameter> parameters = {p};

    ASSERT_THROW(
        helper::base::checkParameterType("checkParameterType", parameters[0], helper::base::Parameter::Type::REFERENCE),
        std::runtime_error);
}

TEST(checkParameterType, Exec_check_parameters_type_value_true)
{
    helper::base::Parameter p;
    p.m_value = "10";
    p.m_type = helper::base::Parameter::Type::VALUE;

    std::vector<helper::base::Parameter> parameters = {p};

    ASSERT_NO_THROW(
        helper::base::checkParameterType("checkParameterType", parameters[0], helper::base::Parameter::Type::VALUE));
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
