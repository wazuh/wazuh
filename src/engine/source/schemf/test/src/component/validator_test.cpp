#include <gtest/gtest.h>

#include <algorithm>
#include <set>

#include <schemf/ivalidator.hpp>
#include <schemf/schema.hpp>

#include <base/behaviour.hpp>

#define GFAIL_CASE "[   CASE   ]"

using namespace base::test;
using namespace schemf;
using namespace testing;

namespace
{

using VT = ValidationToken;
using ST = schemf::Type;
using JT = json::Json::Type;

const std::set<ST> ALLSCHEMATYPES = {ST::BOOLEAN,
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
                                     ST::WILDCARD,
                                     ST::DATE,
                                     ST::DATE_NANOS,
                                     ST::IP,
                                     ST::BINARY,
                                     ST::OBJECT,
                                     ST::NESTED,
                                     ST::GEO_POINT};

const std::set<JT> ALLJTYPES = {JT::Boolean, JT::Number, JT::String, JT::Object};

const json::Json J_BOOL {"true"};
const json::Json J_BYTE {"1"};
const json::Json J_SHORT {"1"};
const json::Json J_INTEGER {std::to_string(int(std::numeric_limits<int8_t>::max()) + 1).c_str()};
const json::Json J_LONG {std::to_string(int64_t(std::numeric_limits<int32_t>::min()) - 1).c_str()};
const json::Json J_FLOAT {"0.1"};
const json::Json J_HALF_FLOAT {"1.0"};
const json::Json J_SCALED_FLOAT {"1.0"};
const json::Json J_DOUBLE {std::to_string(double(std::numeric_limits<float_t>::max()) + 1).c_str()};
const json::Json J_KEYWORD {"\"keyword\""};
const json::Json J_TEXT {"\"text\""};
const json::Json J_WILDCARD {"\"wildcard\""};
const json::Json J_DATE {"\"2020-01-01T01:00:00Z\""};
const json::Json J_DATE_NANOS {"\"2020-01-01T00:00:00.000000000Z\""};
const json::Json J_IP {"\"192.168.0.1\""};
const json::Json J_BINARY {"\"SGksIEkgYW0gTWFyaWFubyBLb3JlbWJsdW0sIGFuZCBJIGFtIGEgV2F6dWggc29mdHdhcmUgZW5naW5lZXI=\""};
const json::Json J_OBJECT {"{}"};
const json::Json J_NESTED {"{}"};
const json::Json J_GEO_POINT {"{}"};

const std::map<ST, json::Json> SCHEMA_JSON = {
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
    {ST::WILDCARD, J_WILDCARD},
    {ST::DATE, J_DATE},
    {ST::DATE_NANOS, J_DATE_NANOS},
    {ST::IP, J_IP},
    {ST::BINARY, J_BINARY},
    {ST::OBJECT, J_OBJECT},
    {ST::NESTED, J_NESTED},
    {ST::GEO_POINT, J_GEO_POINT},
};

DotPath getField(ST stype)
{
    return {fmt::format("field_{}", schemf::typeToStr(stype))};
}

DotPath getArrayField(ST stype)
{
    return {fmt::format("field_{}_array", schemf::typeToStr(stype))};
}

} // namespace

namespace buildvalidationtest
{

// targetField schemaType
// valid schemaTypes(does not need runtime validation)
// valid schemaTypes(does need runtime validation)
// valid jsonTypes(does need runtime validation)
using BuildT = std::tuple<ST, std::set<ST>, std::set<ST>, std::set<JT>>;

class BuildValidation : public TestWithParam<BuildT>
{
protected:
    std::shared_ptr<Schema> schema;

    void SetUp() override
    {
        schema = std::make_shared<Schema>();

        // Add a field for each stype
        for (auto stype : ALLSCHEMATYPES)
        {
            schema->addField(getField(stype), Field(Field::Parameters {.type = stype}));
            schema->addField(getArrayField(stype), Field(Field::Parameters {.type = stype, .isArray = true}));
        }
    }

    std::shared_ptr<IValidator> getValidator() { return schema; }
};

void validateTest(const std::shared_ptr<IValidator>& validator,
                  const DotPath& targetField,
                  const ValidationToken& valToken,
                  bool success,
                  bool runtimeValidation,
                  const std::string& trace)
{
    base::RespOrError<ValidationResult> result;
    EXPECT_NO_THROW(result = validator->validate(targetField, valToken)) << trace << "Threw exception on validation";
    if (success)
    {
        EXPECT_FALSE(base::isError(result)) << trace << "Got validation error: " << base::getError(result).message;
        EXPECT_EQ(runtimeValidation, base::getResponse<ValidationResult>(result).needsRuntimeValidation())
            << trace
            << fmt::format("Expected {}",
                           runtimeValidation ? "to have runtime validation" : "to not have runtime validation");
    }
    else
    {
        EXPECT_TRUE(base::isError(result)) << trace << "Passed validation when it should have failed";
    }
}

TEST_P(BuildValidation, CompatibleSType)
{
    auto [targetType, validSTypesNoRun, validSTypesRun, validJTypesRun] = GetParam();
    auto validator = getValidator();

    auto target = getField(targetType);
    auto targetArray = getArrayField(targetType);

    // Non array success schema validations
    for (auto type : validSTypesNoRun)
    {
        auto valToken = STypeToken::create(type);
        auto trace = fmt::format("{} [targetSType: {}, tokenStype: {}] -> ",
                                 GFAIL_CASE,
                                 schemf::typeToStr(targetType),
                                 schemf::typeToStr(type));
        validateTest(validator, target, valToken, true, false, trace);
    }
    for (auto type : validSTypesRun)
    {
        auto valToken = STypeToken::create(type);
        auto trace = fmt::format("{} [targetSType: {}, tokenStype: {}] -> ",
                                 GFAIL_CASE,
                                 schemf::typeToStr(targetType),
                                 schemf::typeToStr(type));
        validateTest(validator, target, valToken, true, true, trace);
    }

    // Array success schema validations
    for (auto type : validSTypesNoRun)
    {
        auto valToken = STypeToken::create(type, true);
        auto trace = fmt::format("{} [targetSType(ARRAY): {}, tokenStype(ARRAY): {}] -> ",
                                 GFAIL_CASE,
                                 schemf::typeToStr(targetType),
                                 schemf::typeToStr(type));
        validateTest(validator, targetArray, valToken, true, false, trace);
    }
    for (auto type : validSTypesRun)
    {
        auto valToken = STypeToken::create(type, true);
        auto trace = fmt::format("{} [targetSType(ARRAY): {}, tokenStype(ARRAY): {}] -> ",
                                 GFAIL_CASE,
                                 schemf::typeToStr(targetType),
                                 schemf::typeToStr(type));
        validateTest(validator, targetArray, valToken, true, true, trace);
    }
}

TEST_P(BuildValidation, IncompatibleSType)
{
    auto [targetType, validSTypesNoRun, validSTypesRun, validJTypesRun] = GetParam();
    auto validator = getValidator();
    std::set<ST> validSTypes;
    std::set_union(validSTypesNoRun.begin(),
                   validSTypesNoRun.end(),
                   validSTypesRun.begin(),
                   validSTypesRun.end(),
                   std::inserter(validSTypes, validSTypes.end()));

    auto target = getField(targetType);
    auto targetArray = getArrayField(targetType);

    // Non array failure schema validations
    std::set<ST> invalidSTypes;
    std::set_difference(ALLSCHEMATYPES.begin(),
                        ALLSCHEMATYPES.end(),
                        validSTypes.begin(),
                        validSTypes.end(),
                        std::inserter(invalidSTypes, invalidSTypes.end()));
    for (auto type : invalidSTypes)
    {
        auto valToken = STypeToken::create(type);
        auto trace = fmt::format("{} [targetSType: {}, tokenStype: {}] -> ",
                                 GFAIL_CASE,
                                 schemf::typeToStr(targetType),
                                 schemf::typeToStr(type));
        validateTest(validator, target, valToken, false, false, trace);
    }

    // Array failure schema validations
    for (auto type : ALLSCHEMATYPES)
    {
        auto valToken = STypeToken::create(type, false);
        auto trace = fmt::format("{} [targetSType(ARRAY): {}, tokenStype: {}] -> ",
                                 GFAIL_CASE,
                                 schemf::typeToStr(targetType),
                                 schemf::typeToStr(type));
        validateTest(validator, targetArray, valToken, false, false, trace);
    }
    for (auto type : ALLSCHEMATYPES)
    {
        auto valToken = STypeToken::create(type, true);
        auto trace = fmt::format("{} [ARRAY, targetSType: {}, tokenStype(ARRAY): {}] -> ",
                                 GFAIL_CASE,
                                 schemf::typeToStr(targetType),
                                 schemf::typeToStr(type));
        validateTest(validator, target, valToken, false, false, trace);
    }
}

TEST_P(BuildValidation, CompatibleJType)
{
    auto [targetType, validSTypesNoRun, validSTypesRun, validJTypesRun] = GetParam();
    auto validator = getValidator();

    auto target = getField(targetType);
    auto targetArray = getArrayField(targetType);

    // Non array success json validations
    for (auto type : validJTypesRun)
    {
        auto valToken = JTypeToken::create(type);
        auto trace = fmt::format("{} [targetSType: {}, tokenJtype: {}] -> ",
                                 GFAIL_CASE,
                                 schemf::typeToStr(targetType),
                                 json::Json::typeToStr(type));
        validateTest(validator, target, valToken, true, true, trace);
    }

    // Array success json validations
    for (auto type : validJTypesRun)
    {
        auto valToken = JTypeToken::create(type, true);
        auto trace = fmt::format("{} [targetSType(ARRAY): {}, tokenJtype(ARRAY): {}] -> ",
                                 GFAIL_CASE,
                                 schemf::typeToStr(targetType),
                                 json::Json::typeToStr(type));
        validateTest(validator, targetArray, valToken, true, true, trace);
    }
}

TEST_P(BuildValidation, IncompatibleJType)
{
    auto [targetType, validSTypesNoRun, validSTypesRun, validJTypesRun] = GetParam();
    auto validator = getValidator();

    auto target = getField(targetType);
    auto targetArray = getArrayField(targetType);

    // Non array failure json validations
    std::set<JT> invalidJTypes;
    std::set_difference(ALLJTYPES.begin(),
                        ALLJTYPES.end(),
                        validJTypesRun.begin(),
                        validJTypesRun.end(),
                        std::inserter(invalidJTypes, invalidJTypes.end()));
    for (auto type : invalidJTypes)
    {
        auto valToken = JTypeToken::create(type);
        auto trace = fmt::format("{} [targetSType: {}, tokenJtype: {}] -> ",
                                 GFAIL_CASE,
                                 schemf::typeToStr(targetType),
                                 json::Json::typeToStr(type));
        validateTest(validator, target, valToken, false, false, trace);
    }

    // Array failure json validations
    for (auto type : ALLJTYPES)
    {
        auto valToken = JTypeToken::create(type, false);
        auto trace = fmt::format("{} [targetSType(ARRAY): {}, tokenJtype: {}] -> ",
                                 GFAIL_CASE,
                                 schemf::typeToStr(targetType),
                                 json::Json::typeToStr(type));
        validateTest(validator, targetArray, valToken, false, false, trace);
    }
    for (auto type : ALLJTYPES)
    {
        auto valToken = JTypeToken::create(type, true);
        auto trace = fmt::format("{} [ARRAY, targetSType: {}, tokenJtype(ARRAY): {}] -> ",
                                 GFAIL_CASE,
                                 schemf::typeToStr(targetType),
                                 json::Json::typeToStr(type));
        validateTest(validator, target, valToken, false, false, trace);
    }
}

TEST_P(BuildValidation, JValueCompatible)
{
    auto [targetType, validSTypesNoRun, validSTypesRun, validJTypesRun] = GetParam();
    auto validator = getValidator();

    auto target = getField(targetType);
    auto targetArray = getArrayField(targetType);

    std::set<ST> validSTypes;
    std::set_union(validSTypesNoRun.begin(),
                   validSTypesNoRun.end(),
                   validSTypesRun.begin(),
                   validSTypesRun.end(),
                   std::inserter(validSTypes, validSTypes.end()));

    // Non array success json validations
    for (auto type : validSTypesNoRun)
    {
        auto valToken = ValueToken::create(SCHEMA_JSON.at(type));
        auto trace = fmt::format("{} [targetSType: {}, tokenJvalue: {}] -> ",
                                 GFAIL_CASE,
                                 schemf::typeToStr(targetType),
                                 SCHEMA_JSON.at(type).str());
        validateTest(validator, target, valToken, true, false, trace);
    }

    // Array success json validations
    for (auto type : validSTypesNoRun)
    {
        json::Json value;
        value.setArray();
        value.appendJson(SCHEMA_JSON.at(type));
        auto valToken = ValueToken::create(value);
        auto trace = fmt::format("{} [targetSType(ARRAY): {}, tokenJvalue(ARRAY): {}] -> ",
                                 GFAIL_CASE,
                                 schemf::typeToStr(targetType),
                                 SCHEMA_JSON.at(type).str());
        validateTest(validator, targetArray, valToken, true, false, trace);
    }
}

INSTANTIATE_TEST_SUITE_P(
    SchemvalTest,
    BuildValidation,
    Values(BuildT(ST::BOOLEAN, {ST::BOOLEAN}, {}, {JT::Boolean}),
           BuildT(ST::BYTE, {ST::BYTE, ST::SHORT}, {ST::INTEGER, ST::LONG}, {JT::Number}),
           BuildT(ST::SHORT, {ST::BYTE, ST::SHORT}, {ST::INTEGER, ST::LONG}, {JT::Number}),
           BuildT(ST::INTEGER, {ST::BYTE, ST::SHORT, ST::INTEGER}, {ST::LONG}, {JT::Number}),
           BuildT(ST::LONG, {ST::BYTE, ST::SHORT, ST::INTEGER, ST::LONG}, {}, {JT::Number}),
           BuildT(ST::FLOAT, {ST::FLOAT, ST::HALF_FLOAT, ST::SCALED_FLOAT}, {ST::DOUBLE}, {JT::Number}),
           BuildT(ST::HALF_FLOAT, {ST::FLOAT, ST::HALF_FLOAT, ST::SCALED_FLOAT}, {ST::DOUBLE}, {JT::Number}),
           BuildT(ST::SCALED_FLOAT, {ST::FLOAT, ST::HALF_FLOAT, ST::SCALED_FLOAT}, {ST::DOUBLE}, {JT::Number}),
           BuildT(ST::DOUBLE, {ST::FLOAT, ST::HALF_FLOAT, ST::SCALED_FLOAT, ST::DOUBLE}, {}, {JT::Number}),
           BuildT(ST::KEYWORD,
                  {ST::TEXT, ST::KEYWORD, ST::WILDCARD, ST::DATE, ST::DATE_NANOS, ST::IP, ST::BINARY},
                  {},
                  {JT::String}),
           BuildT(ST::TEXT,
                  {ST::TEXT, ST::KEYWORD, ST::WILDCARD, ST::DATE, ST::DATE_NANOS, ST::IP, ST::BINARY},
                  {},
                  {JT::String}),
           BuildT(ST::WILDCARD,
                  {ST::WILDCARD, ST::TEXT, ST::KEYWORD, ST::DATE, ST::DATE_NANOS, ST::IP, ST::BINARY},
                  {},
                  {JT::String}),
           BuildT(ST::DATE, {ST::DATE}, {ST::TEXT, ST::WILDCARD, ST::KEYWORD}, {JT::String}),
           BuildT(ST::DATE_NANOS, {ST::DATE_NANOS}, {ST::TEXT, ST::WILDCARD, ST::KEYWORD}, {JT::String}),
           BuildT(ST::IP, {ST::IP}, {ST::TEXT, ST::WILDCARD, ST::KEYWORD}, {JT::String}),
           BuildT(ST::BINARY, {ST::BINARY}, {ST::TEXT, ST::WILDCARD, ST::KEYWORD}, {JT::String}),
           BuildT(ST::OBJECT, {ST::OBJECT}, {}, {JT::Object}),
           BuildT(ST::NESTED, {ST::NESTED}, {}, {JT::Object}),
           BuildT(ST::GEO_POINT, {ST::GEO_POINT}, {}, {JT::Object})),
    [](const testing::TestParamInfo<BuildValidation::ParamType>& info)
    {
        std::string name = schemf::typeToStr(std::get<0>(info.param));
        return name;
    });

} // namespace buildvalidationtest
