#include <gtest/gtest.h>

#include <algorithm>
#include <set>

#include <schemf/mockSchema.hpp>
#include <schemval/validator.hpp>

#include <base/test/behaviour.hpp>

#define GFAIL_CASE "[   CASE   ]"

using namespace schemval;
using namespace base::test;
using namespace schemf;
using namespace schemf::mocks;
using namespace testing;

using VT = ValidationToken;
using ST = schemf::Type;
using JT = json::Json::Type;

const static std::set<ST> ALLSCHEMATYPES = {ST::BOOLEAN,
                                            ST::BYTE,
                                            ST::SHORT,
                                            ST::INTEGER,
                                            ST::LONG,
                                            ST::FLOAT,
                                            ST::HALF_FLOAT,
                                            ST::SCALED_FLOAT,
                                            ST::DOUBLE,
                                            ST::KEYWORD,
                                            ST::TEXT,
                                            ST::DATE,
                                            ST::DATE_NANOS,
                                            ST::IP,
                                            ST::BINARY,
                                            ST::OBJECT,
                                            ST::NESTED,
                                            ST::GEO_POINT};

const static std::set<JT> ALLJTYPES = {JT::Boolean, JT::Number, JT::String, JT::Array, JT::Object};

const static json::Json J_BOOL {"true"};
const static json::Json J_BYTE {"1"};
const static json::Json J_SHORT {"1"};
const static json::Json J_INTEGER {std::to_string(int(std::numeric_limits<int8_t>::max()) + 1).c_str()};
const static json::Json J_LONG {std::to_string(int64_t(std::numeric_limits<int32_t>::min()) - 1).c_str()};
const static json::Json J_FLOAT {"0.1"};
const static json::Json J_HALF_FLOAT {"1.0"};
const static json::Json J_SCALED_FLOAT {"1.0"};
const static json::Json J_DOUBLE {std::to_string(double(std::numeric_limits<float_t>::max()) + 1).c_str()};
const static json::Json J_KEYWORD {"\"keyword\""};
const static json::Json J_TEXT {"\"text\""};
const static json::Json J_DATE {"\"2020-01-01\""};
const static json::Json J_DATE_NANOS {"\"2020-01-01T00:00:00.000000000Z\""};
const static json::Json J_IP {"\"192.168.0.1\""};
const static json::Json J_BINARY {"\"binary\""};
const static json::Json J_OBJECT {};
const static json::Json J_NESTED {};
const static json::Json J_GEO_POINT {};

const static std::map<ST, json::Json> SCHEMA_JSON = {
    {ST::BOOLEAN, J_BOOL},
    {ST::BYTE, J_BYTE},
    {ST::SHORT, J_SHORT},
    {ST::INTEGER, J_INTEGER},
    {ST::LONG, J_LONG},
    {ST::FLOAT, J_FLOAT},
    {ST::HALF_FLOAT, J_HALF_FLOAT},
    {ST::SCALED_FLOAT, J_SCALED_FLOAT},
    {ST::DOUBLE, J_DOUBLE},
    {ST::KEYWORD, J_KEYWORD},
    {ST::TEXT, J_TEXT},
    {ST::DATE, J_DATE},
    {ST::DATE_NANOS, J_DATE_NANOS},
    {ST::IP, J_IP},
    {ST::BINARY, J_BINARY},
    {ST::OBJECT, J_OBJECT},
    {ST::NESTED, J_NESTED},
    {ST::GEO_POINT, J_GEO_POINT},
};

namespace buildvalidationtest
{

// targetField schemaType
// valid schemaTypes(does not need runtime validation)
// valid schemaTypes(does need runtime validation)
// valid jsonTypes(does not need runtime validation)
// valid jsonTypes(does need runtime validation)
using BuildT = std::tuple<ST, std::set<ST>, std::set<ST>, std::set<JT>, std::set<JT>>;

class BuildValidation : public TestWithParam<BuildT>
{
};

void validateTest(const std::shared_ptr<IValidator>& validator,
                  const DotPath& targetField,
                  const ValidationToken& valToken,
                  bool success,
                  const std::string& trace)
{
    base::OptError error;
    EXPECT_NO_THROW(error = validator->validate(targetField, valToken)) << trace << "Threw exception on validation";
    if (success)
    {
        EXPECT_FALSE(error) << trace << "Got validation error: " << error.value().message;
    }
    else
    {
        EXPECT_TRUE(error) << trace << "Passed validation when it should have failed";
    }
}

auto getInitialState(const std::string& targetField)
{
    auto schema = std::make_shared<MockSchema>();
    auto validator = std::make_shared<Validator>(schema);

    return std::make_tuple(schema, validator, DotPath(targetField));
}

TEST_P(BuildValidation, CompatibleSType)
{
    auto [targetType, validSTypesNoRun, validSTypesRun, validJTypesNoRun, validJTypesRun] = GetParam();
    auto [schema, validator, targetField] = getInitialState("test.field");
    std::set<ST> validSTypes;
    std::set_union(validSTypesNoRun.begin(),
                   validSTypesNoRun.end(),
                   validSTypesRun.begin(),
                   validSTypesRun.end(),
                   std::inserter(validSTypes, validSTypes.end()));

    // Non array success schema validations
    for (auto type : validSTypes)
    {
        EXPECT_CALL(*schema, hasField(targetField)).WillOnce(Return(true));
        EXPECT_CALL(*schema, getType(targetField)).WillOnce(Return(targetType));
        EXPECT_CALL(*schema, isArray(targetField)).WillRepeatedly(Return(false));

        ValidationToken valToken(type);
        auto trace = fmt::format("{} [targetSType: {}, tokenStype: {}] -> ",
                                 GFAIL_CASE,
                                 schemf::typeToStr(targetType),
                                 schemf::typeToStr(type));
        validateTest(validator, "test.field", valToken, true, trace);
    }

    // Array success schema validations
    for (auto type : validSTypes)
    {
        EXPECT_CALL(*schema, hasField(targetField)).WillOnce(Return(true));
        EXPECT_CALL(*schema, getType(targetField)).WillOnce(Return(targetType));
        EXPECT_CALL(*schema, isArray(targetField)).WillRepeatedly(Return(true));

        ValidationToken valToken(type, true);
        auto trace = fmt::format("{} [targetSType(ARRAY): {}, tokenStype(ARRAY): {}] -> ",
                                 GFAIL_CASE,
                                 schemf::typeToStr(targetType),
                                 schemf::typeToStr(type));
        validateTest(validator, "test.field", valToken, true, trace);
    }
}

TEST_P(BuildValidation, IncompatibleSType)
{
    auto [targetType, validSTypesNoRun, validSTypesRun, validJTypesNoRun, validJTypesRun] = GetParam();
    auto [schema, validator, targetField] = getInitialState("test.field");
    std::set<ST> validSTypes;
    std::set_union(validSTypesNoRun.begin(),
                   validSTypesNoRun.end(),
                   validSTypesRun.begin(),
                   validSTypesRun.end(),
                   std::inserter(validSTypes, validSTypes.end()));

    // Non array failure schema validations
    std::set<ST> invalidSTypes;
    std::set_difference(ALLSCHEMATYPES.begin(),
                        ALLSCHEMATYPES.end(),
                        validSTypes.begin(),
                        validSTypes.end(),
                        std::inserter(invalidSTypes, invalidSTypes.end()));
    for (auto type : invalidSTypes)
    {
        EXPECT_CALL(*schema, hasField(targetField)).WillOnce(Return(true));
        EXPECT_CALL(*schema, getType(targetField)).WillOnce(Return(targetType));
        EXPECT_CALL(*schema, isArray(targetField)).WillRepeatedly(Return(false));

        ValidationToken valToken(type);
        auto trace = fmt::format("{} [targetSType: {}, tokenStype: {}] -> ",
                                 GFAIL_CASE,
                                 schemf::typeToStr(targetType),
                                 schemf::typeToStr(type));
        validateTest(validator, "test.field", valToken, false, trace);
    }

    // Array failure schema validations
    for (auto type : ALLSCHEMATYPES)
    {
        EXPECT_CALL(*schema, hasField(targetField)).WillOnce(Return(true));
        EXPECT_CALL(*schema, isArray(targetField)).WillRepeatedly(Return(true));

        ValidationToken valToken(type, false);
        auto trace = fmt::format("{} [targetSType(ARRAY): {}, tokenStype: {}] -> ",
                                 GFAIL_CASE,
                                 schemf::typeToStr(targetType),
                                 schemf::typeToStr(type));
        validateTest(validator, "test.field", valToken, false, trace);
    }
    for (auto type : ALLSCHEMATYPES)
    {
        EXPECT_CALL(*schema, hasField(targetField)).WillOnce(Return(true));
        EXPECT_CALL(*schema, isArray(targetField)).WillRepeatedly(Return(false));

        ValidationToken valToken(type, true);
        auto trace = fmt::format("{} [ARRAY, targetSType: {}, tokenStype(ARRAY): {}] -> ",
                                 GFAIL_CASE,
                                 schemf::typeToStr(targetType),
                                 schemf::typeToStr(type));
        validateTest(validator, "test.field", valToken, false, trace);
    }
}

TEST_P(BuildValidation, CompatibleJType)
{
    auto [targetType, validSTypesNoRun, validSTypesRun, validJTypesNoRun, validJTypesRun] = GetParam();
    auto [schema, validator, targetField] = getInitialState("test.field");
    std::set<JT> validJTypes;
    std::set_union(validJTypesNoRun.begin(),
                   validJTypesNoRun.end(),
                   validJTypesRun.begin(),
                   validJTypesRun.end(),
                   std::inserter(validJTypes, validJTypes.end()));

    // Non array success json validations
    for (auto type : validJTypes)
    {
        EXPECT_CALL(*schema, hasField(targetField)).WillOnce(Return(true));
        EXPECT_CALL(*schema, getType(targetField)).WillOnce(Return(targetType));
        EXPECT_CALL(*schema, isArray(targetField)).WillRepeatedly(Return(false));

        ValidationToken valToken(type);
        auto trace = fmt::format("{} [targetSType: {}, tokenJtype: {}] -> ",
                                 GFAIL_CASE,
                                 schemf::typeToStr(targetType),
                                 json::Json::typeToStr(type));
        validateTest(validator, "test.field", valToken, true, trace);
    }

    // Array success json validations
    for (auto type : validJTypes)
    {
        EXPECT_CALL(*schema, hasField(targetField)).WillOnce(Return(true));
        EXPECT_CALL(*schema, getType(targetField)).WillOnce(Return(targetType));
        EXPECT_CALL(*schema, isArray(targetField)).WillRepeatedly(Return(true));

        ValidationToken valToken(type, true);
        auto trace = fmt::format("{} [targetSType(ARRAY): {}, tokenJtype(ARRAY): {}] -> ",
                                 GFAIL_CASE,
                                 schemf::typeToStr(targetType),
                                 json::Json::typeToStr(type));
        validateTest(validator, "test.field", valToken, true, trace);
    }
}

TEST_P(BuildValidation, IncompatibleJType)
{
    auto [targetType, validSTypesNoRun, validSTypesRun, validJTypesNoRun, validJTypesRun] = GetParam();
    auto [schema, validator, targetField] = getInitialState("test.field");
    std::set<JT> validJTypes;
    std::set_union(validJTypesNoRun.begin(),
                   validJTypesNoRun.end(),
                   validJTypesRun.begin(),
                   validJTypesRun.end(),
                   std::inserter(validJTypes, validJTypes.end()));

    // Non array failure json validations
    std::set<JT> invalidJTypes;
    std::set_difference(ALLJTYPES.begin(),
                        ALLJTYPES.end(),
                        validJTypes.begin(),
                        validJTypes.end(),
                        std::inserter(invalidJTypes, invalidJTypes.end()));
    for (auto type : invalidJTypes)
    {
        EXPECT_CALL(*schema, hasField(targetField)).WillOnce(Return(true));
        EXPECT_CALL(*schema, getType(targetField)).WillOnce(Return(targetType));
        EXPECT_CALL(*schema, isArray(targetField)).WillRepeatedly(Return(false));

        ValidationToken valToken(type);
        auto trace = fmt::format("{} [targetSType: {}, tokenJtype: {}] -> ",
                                 GFAIL_CASE,
                                 schemf::typeToStr(targetType),
                                 json::Json::typeToStr(type));
        validateTest(validator, "test.field", valToken, false, trace);
    }

    // Array failure json validations
    for (auto type : ALLJTYPES)
    {
        EXPECT_CALL(*schema, hasField(targetField)).WillOnce(Return(true));
        EXPECT_CALL(*schema, isArray(targetField)).WillRepeatedly(Return(true));

        ValidationToken valToken(type, false);
        auto trace = fmt::format("{} [targetSType(ARRAY): {}, tokenJtype: {}] -> ",
                                 GFAIL_CASE,
                                 schemf::typeToStr(targetType),
                                 json::Json::typeToStr(type));
        validateTest(validator, "test.field", valToken, false, trace);
    }
    for (auto type : ALLJTYPES)
    {
        EXPECT_CALL(*schema, hasField(targetField)).WillOnce(Return(true));
        EXPECT_CALL(*schema, isArray(targetField)).WillRepeatedly(Return(false));

        ValidationToken valToken(type, true);
        auto trace = fmt::format("{} [ARRAY, targetSType: {}, tokenJtype(ARRAY): {}] -> ",
                                 GFAIL_CASE,
                                 schemf::typeToStr(targetType),
                                 json::Json::typeToStr(type));
        validateTest(validator, "test.field", valToken, false, trace);
    }
}

TEST_P(BuildValidation, JValueCompatible)
{
    auto [targetType, validSTypesNoRun, validSTypesRun, validJTypesNoRun, validJTypesRun] = GetParam();
    auto [schema, validator, targetField] = getInitialState("test.field");
    std::set<ST> validSTypes;
    std::set_union(validSTypesNoRun.begin(),
                   validSTypesNoRun.end(),
                   validSTypesRun.begin(),
                   validSTypesRun.end(),
                   std::inserter(validSTypes, validSTypes.end()));

    // Non array success json validations
    for (auto type : validSTypesNoRun)
    {
        EXPECT_CALL(*schema, hasField(targetField)).WillRepeatedly(Return(true));
        EXPECT_CALL(*schema, getType(targetField)).WillRepeatedly(Return(targetType));
        EXPECT_CALL(*schema, isArray(targetField)).WillRepeatedly(Return(false));

        ValidationToken valToken(SCHEMA_JSON.at(type));
        auto trace = fmt::format("{} [targetSType: {}, tokenJvalue: {}] -> ",
                                 GFAIL_CASE,
                                 schemf::typeToStr(targetType),
                                 SCHEMA_JSON.at(type).str());
        validateTest(validator, "test.field", valToken, true, trace);
    }

    // Array success json validations
    for (auto type : validSTypesNoRun)
    {
        EXPECT_CALL(*schema, hasField(targetField)).WillRepeatedly(Return(true));
        EXPECT_CALL(*schema, getType(targetField)).WillRepeatedly(Return(targetType));
        EXPECT_CALL(*schema, isArray(targetField)).WillRepeatedly(Return(true));

        json::Json value;
        value.setArray();
        value.appendJson(SCHEMA_JSON.at(type));
        ValidationToken valToken(value);
        auto trace = fmt::format("{} [targetSType(ARRAY): {}, tokenJvalue(ARRAY): {}] -> ",
                                 GFAIL_CASE,
                                 schemf::typeToStr(targetType),
                                 SCHEMA_JSON.at(type).str());
        validateTest(validator, "test.field", valToken, true, trace);
    }
}

INSTANTIATE_TEST_SUITE_P(
    SchemvalTest,
    BuildValidation,
    Values(
        BuildT(ST::BOOLEAN, {ST::BOOLEAN}, {}, {JT::Boolean}, {}),
        BuildT(ST::BYTE,
               {ST::BYTE, ST::SHORT},
               {ST::INTEGER, ST::LONG, ST::FLOAT, ST::HALF_FLOAT, ST::SCALED_FLOAT, ST::DOUBLE},
               {},
               {JT::Number}),
        BuildT(ST::SHORT,
               {ST::BYTE, ST::SHORT},
               {ST::INTEGER, ST::LONG, ST::FLOAT, ST::HALF_FLOAT, ST::SCALED_FLOAT, ST::DOUBLE},
               {},
               {JT::Number}),
        BuildT(ST::INTEGER,
               {ST::BYTE, ST::SHORT, ST::INTEGER},
               {ST::LONG, ST::FLOAT, ST::HALF_FLOAT, ST::SCALED_FLOAT, ST::DOUBLE},
               {},
               {JT::Number}),
        BuildT(ST::LONG,
               {ST::BYTE, ST::SHORT, ST::INTEGER, ST::LONG},
               {ST::FLOAT, ST::HALF_FLOAT, ST::SCALED_FLOAT, ST::DOUBLE},
               {},
               {JT::Number}),
        BuildT(ST::FLOAT,
               {ST::BYTE, ST::SHORT, ST::INTEGER, ST::LONG, ST::FLOAT, ST::HALF_FLOAT, ST::SCALED_FLOAT},
               {ST::DOUBLE},
               {},
               {JT::Number}),
        BuildT(ST::HALF_FLOAT,
               {ST::BYTE, ST::SHORT, ST::INTEGER, ST::LONG, ST::FLOAT, ST::HALF_FLOAT, ST::SCALED_FLOAT},
               {ST::DOUBLE},
               {},
               {JT::Number}),
        BuildT(ST::SCALED_FLOAT,
               {ST::BYTE, ST::SHORT, ST::INTEGER, ST::LONG, ST::FLOAT, ST::HALF_FLOAT, ST::SCALED_FLOAT},
               {ST::DOUBLE},
               {},
               {JT::Number}),
        BuildT(ST::DOUBLE,
               {ST::BYTE, ST::SHORT, ST::INTEGER, ST::LONG, ST::FLOAT, ST::HALF_FLOAT, ST::SCALED_FLOAT, ST::DOUBLE},
               {},
               {},
               {JT::Number}),
        BuildT(
            ST::KEYWORD, {ST::TEXT, ST::KEYWORD, ST::DATE, ST::DATE_NANOS, ST::IP, ST::BINARY}, {}, {JT::String}, {}),
        BuildT(ST::TEXT, {ST::TEXT, ST::KEYWORD, ST::DATE, ST::DATE_NANOS, ST::IP, ST::BINARY}, {}, {JT::String}, {}),
        BuildT(ST::DATE, {ST::DATE}, {ST::TEXT, ST::KEYWORD}, {}, {JT::String}),
        BuildT(ST::DATE_NANOS, {ST::DATE_NANOS}, {}, {JT::String}, {}),
        BuildT(ST::IP, {ST::IP}, {ST::TEXT, ST::KEYWORD}, {}, {JT::String}),
        BuildT(ST::BINARY, {ST::BINARY}, {ST::TEXT, ST::KEYWORD}, {}, {JT::String}),
        BuildT(ST::OBJECT, {ST::OBJECT}, {}, {JT::Object}, {}),
        BuildT(ST::NESTED, {ST::NESTED}, {}, {JT::Object}, {}),
        BuildT(ST::GEO_POINT, {ST::GEO_POINT}, {}, {JT::Object}, {})),
    [](const testing::TestParamInfo<BuildValidation::ParamType>& info)
    {
        std::string name = schemf::typeToStr(std::get<0>(info.param));
        return name;
    });

} // namespace buildvalidationtest

namespace runtimevalidationtest
{
// targetField schemaType
// array/notArray
// json value
// success/failure
using RunT = std::tuple<ST, bool, json::Json, bool>;

class RuntimeValidation : public TestWithParam<RunT>
{
};

TEST_P(RuntimeValidation, Value)
{
    auto [targetType, isArray, value, success] = GetParam();
    auto [schema, validator, targetField] = buildvalidationtest::getInitialState("test.field");

    EXPECT_CALL(*schema, hasField(targetField)).WillOnce(Return(true));
    EXPECT_CALL(*schema, getType(targetField)).WillOnce(Return(targetType));
    EXPECT_CALL(*schema, isArray(targetField)).WillRepeatedly(Return(isArray));

    auto runtimeValidatorResp = validator->getRuntimeValidator(targetField, isArray);
    if (success)
    {
        EXPECT_FALSE(base::isError(runtimeValidatorResp));
    }
    else
    {
        if (base::isError(runtimeValidatorResp))
        {
            SUCCEED();
            return;
        }
    }
    auto runtimeValidator = base::getResponse<RuntimeValidator>(runtimeValidatorResp);

    auto trace = fmt::format("{} [targetSType: {}, isArray: {}, value: {}] -> ",
                             GFAIL_CASE,
                             schemf::typeToStr(targetType),
                             isArray,
                             value.str());

    bool ok;
    EXPECT_NO_THROW(ok = runtimeValidator(value)) << trace << "Threw exception on validation";
    EXPECT_EQ(ok, success) << trace << "Got validation error";
}

using J = json::Json;
INSTANTIATE_TEST_SUITE_P(SchemvalTest,
                         RuntimeValidation,
                         Values(RunT(ST::BOOLEAN, false, J_BOOL, true),
                                RunT(ST::BOOLEAN, true, J_BOOL, false),
                                RunT(ST::BOOLEAN, true, J("[false]"), true)));

} // namespace runtimevalidationtest
