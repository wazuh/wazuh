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
                                     ST::MATCH_ONLY_TEXT,
                                     ST::WILDCARD,
                                     ST::CONSTANT_KEYWORD,
                                     ST::DATE,
                                     ST::DATE_NANOS,
                                     ST::IP,
                                     ST::BINARY,
                                     ST::OBJECT,
                                     ST::NESTED,
                                     ST::FLAT_OBJECT,
                                     ST::GEO_POINT,
                                     ST::UNSIGNED_LONG,
                                     ST::COMPLETION,
                                     ST::SEARCH_AS_YOU_TYPE,
                                     ST::TOKEN_COUNT,
                                     ST::SEMANTIC,
                                     ST::JOIN,
                                     ST::KNN_VECTOR,
                                     ST::SPARSE_VECTOR,
                                     ST::RANK_FEATURE,
                                     ST::RANK_FEATURES,
                                     ST::PERCOLATOR,
                                     ST::STAR_TREE,
                                     ST::DERIVED,
                                     ST::INTEGER_RANGE,
                                     ST::LONG_RANGE,
                                     ST::FLOAT_RANGE,
                                     ST::DOUBLE_RANGE,
                                     ST::DATE_RANGE,
                                     ST::IP_RANGE};

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
const json::Json J_MATCH_ONLY_TEXT {"\"match_only_text\""};
const json::Json J_WILDCARD {"\"wildcard\""};
const json::Json J_CONSTANT_KEYWORD {"\"constant_keyword\""};
const json::Json J_DATE {"\"2020-01-01T01:00:00Z\""};
const json::Json J_DATE_NANOS {"\"2020-01-01T00:00:00.000000000Z\""};
const json::Json J_IP {"\"192.168.0.1\""};
const json::Json J_BINARY {"\"SGksIEkgYW0gTWFyaWFubyBLb3JlbWJsdW0sIGFuZCBJIGFtIGEgV2F6dWggc29mdHdhcmUgZW5naW5lZXI=\""};
const json::Json J_OBJECT {"{}"};
const json::Json J_NESTED {"{}"};
const json::Json J_FLAT_OBJECT {"{}"};
const json::Json J_GEO_POINT {"{}"};
const json::Json J_UNSIGNED_LONG {"1"};
const json::Json J_COMPLETION {"\"completion\""};
const json::Json J_SEARCH_AS_YOU_TYPE {"\"search_as_you_type\""};
const json::Json J_TOKEN_COUNT {"1"};
const json::Json J_SEMANTIC {"\"semantic\""};
const json::Json J_JOIN {"{}"};
// Incompatible types - these types should not be used for validation tests as they are marked incompatible
const json::Json J_KNN_VECTOR {"null"};
const json::Json J_SPARSE_VECTOR {"null"};
const json::Json J_RANK_FEATURE {"null"};
const json::Json J_RANK_FEATURES {"null"};
const json::Json J_PERCOLATOR {"null"};
const json::Json J_STAR_TREE {"null"};
const json::Json J_DERIVED {"null"};
const json::Json J_INTEGER_RANGE {"null"};
const json::Json J_LONG_RANGE {"null"};
const json::Json J_FLOAT_RANGE {"null"};
const json::Json J_DOUBLE_RANGE {"null"};
const json::Json J_DATE_RANGE {"null"};
const json::Json J_IP_RANGE {"null"};

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
    {ST::MATCH_ONLY_TEXT, J_MATCH_ONLY_TEXT},
    {ST::WILDCARD, J_WILDCARD},
    {ST::CONSTANT_KEYWORD, J_CONSTANT_KEYWORD},
    {ST::DATE, J_DATE},
    {ST::DATE_NANOS, J_DATE_NANOS},
    {ST::IP, J_IP},
    {ST::BINARY, J_BINARY},
    {ST::OBJECT, J_OBJECT},
    {ST::NESTED, J_NESTED},
    {ST::FLAT_OBJECT, J_FLAT_OBJECT},
    {ST::GEO_POINT, J_GEO_POINT},
    {ST::UNSIGNED_LONG, J_UNSIGNED_LONG},
    {ST::COMPLETION, J_COMPLETION},
    {ST::SEARCH_AS_YOU_TYPE, J_SEARCH_AS_YOU_TYPE},
    {ST::TOKEN_COUNT, J_TOKEN_COUNT},
    {ST::SEMANTIC, J_SEMANTIC},
    {ST::JOIN, J_JOIN},
    {ST::KNN_VECTOR, J_KNN_VECTOR},
    {ST::SPARSE_VECTOR, J_SPARSE_VECTOR},
    {ST::RANK_FEATURE, J_RANK_FEATURE},
    {ST::RANK_FEATURES, J_RANK_FEATURES},
    {ST::PERCOLATOR, J_PERCOLATOR},
    {ST::STAR_TREE, J_STAR_TREE},
    {ST::DERIVED, J_DERIVED},
    {ST::INTEGER_RANGE, J_INTEGER_RANGE},
    {ST::LONG_RANGE, J_LONG_RANGE},
    {ST::FLOAT_RANGE, J_FLOAT_RANGE},
    {ST::DOUBLE_RANGE, J_DOUBLE_RANGE},
    {ST::DATE_RANGE, J_DATE_RANGE},
    {ST::IP_RANGE, J_IP_RANGE}
};

DotPath getField(ST stype)
{
    return {fmt::format("field_{}", schemf::typeToStr(stype))};
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
}

TEST_P(BuildValidation, CompatibleJType)
{
    auto [targetType, validSTypesNoRun, validSTypesRun, validJTypesRun] = GetParam();
    auto validator = getValidator();

    auto target = getField(targetType);

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
}

TEST_P(BuildValidation, IncompatibleJType)
{
    auto [targetType, validSTypesNoRun, validSTypesRun, validJTypesRun] = GetParam();
    auto validator = getValidator();

    auto target = getField(targetType);

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
}

TEST_P(BuildValidation, JValueCompatible)
{
    auto [targetType, validSTypesNoRun, validSTypesRun, validJTypesRun] = GetParam();
    auto validator = getValidator();

    auto target = getField(targetType);

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
}

INSTANTIATE_TEST_SUITE_P(
    SchemvalTest,
    BuildValidation,
    Values(BuildT(ST::BOOLEAN, {ST::BOOLEAN}, {}, {JT::Boolean}),
           BuildT(ST::BYTE, {ST::BYTE}, {ST::INTEGER, ST::LONG, ST::SHORT}, {JT::Number}),
           BuildT(ST::SHORT, {ST::BYTE, ST::SHORT}, {ST::INTEGER, ST::LONG}, {JT::Number}),
           BuildT(ST::INTEGER, {ST::BYTE, ST::SHORT, ST::INTEGER}, {ST::LONG}, {JT::Number}),
           BuildT(ST::LONG, {ST::BYTE, ST::SHORT, ST::INTEGER, ST::LONG}, {}, {JT::Number}),
           BuildT(ST::FLOAT, {ST::FLOAT, ST::HALF_FLOAT, ST::SCALED_FLOAT}, {ST::DOUBLE}, {JT::Number}),
           BuildT(ST::HALF_FLOAT, {ST::HALF_FLOAT}, {ST::FLOAT, ST::SCALED_FLOAT, ST::DOUBLE}, {JT::Number}),
           BuildT(ST::SCALED_FLOAT, {ST::FLOAT, ST::HALF_FLOAT, ST::SCALED_FLOAT}, {ST::DOUBLE}, {JT::Number}),
           BuildT(ST::DOUBLE, {ST::FLOAT, ST::HALF_FLOAT, ST::SCALED_FLOAT, ST::DOUBLE}, {}, {JT::Number}),
           BuildT(ST::KEYWORD,
                  {ST::TEXT, ST::KEYWORD, ST::MATCH_ONLY_TEXT, ST::CONSTANT_KEYWORD, ST::WILDCARD,
                    ST::DATE, ST::DATE_NANOS, ST::IP, ST::BINARY, ST::COMPLETION, ST::SEARCH_AS_YOU_TYPE,
                    ST::SEMANTIC, ST::WILDCARD},
                  {},
                  {JT::String}),
           BuildT(ST::MATCH_ONLY_TEXT,
                  {ST::MATCH_ONLY_TEXT, ST::TEXT, ST::KEYWORD, ST::CONSTANT_KEYWORD, ST::WILDCARD,
                    ST::DATE, ST::DATE_NANOS, ST::IP, ST::BINARY, ST::COMPLETION, ST::SEARCH_AS_YOU_TYPE,
                    ST::SEMANTIC, ST::WILDCARD},
                  {},
                  {JT::String}),
           BuildT(ST::CONSTANT_KEYWORD,
                  {ST::CONSTANT_KEYWORD, ST::TEXT, ST::KEYWORD, ST::MATCH_ONLY_TEXT, ST::WILDCARD,
                    ST::DATE, ST::DATE_NANOS, ST::IP, ST::BINARY, ST::COMPLETION, ST::SEARCH_AS_YOU_TYPE,
                    ST::SEMANTIC, ST::WILDCARD},
                  {},
                  {JT::String}),
           BuildT(ST::TEXT,
                  {ST::TEXT, ST::KEYWORD, ST::MATCH_ONLY_TEXT, ST::CONSTANT_KEYWORD, ST::WILDCARD,
                    ST::DATE, ST::DATE_NANOS, ST::IP, ST::BINARY, ST::COMPLETION, ST::SEARCH_AS_YOU_TYPE,
                    ST::SEMANTIC, ST::WILDCARD},
                  {},
                  {JT::String}),
           BuildT(ST::WILDCARD,
                  {ST::WILDCARD, ST::TEXT, ST::KEYWORD, ST::MATCH_ONLY_TEXT, ST::CONSTANT_KEYWORD,
                    ST::DATE, ST::DATE_NANOS, ST::IP, ST::BINARY, ST::COMPLETION, ST::SEARCH_AS_YOU_TYPE,
                    ST::SEMANTIC},
                  {},
                  {JT::String}),
           BuildT(ST::DATE, {ST::DATE}, {ST::TEXT, ST::WILDCARD, ST::KEYWORD}, {JT::String}),
           BuildT(ST::DATE_NANOS, {ST::DATE_NANOS}, {ST::TEXT, ST::WILDCARD, ST::KEYWORD}, {JT::String}),
           BuildT(ST::IP, {ST::IP}, {ST::TEXT, ST::WILDCARD, ST::KEYWORD}, {JT::String}),
           BuildT(ST::BINARY, {ST::BINARY}, {ST::TEXT, ST::WILDCARD, ST::KEYWORD}, {JT::String}),
           BuildT(ST::OBJECT, {ST::OBJECT}, {}, {JT::Object}),
           BuildT(ST::NESTED, {ST::NESTED}, {}, {JT::Object}),
           BuildT(ST::FLAT_OBJECT, {ST::FLAT_OBJECT}, {}, {JT::Object}),
           BuildT(ST::TOKEN_COUNT, {ST::TOKEN_COUNT}, {}, {JT::Number}),
           BuildT(ST::SEMANTIC,
                   {ST::SEMANTIC, ST::SEARCH_AS_YOU_TYPE, ST::KEYWORD, ST::MATCH_ONLY_TEXT, ST::CONSTANT_KEYWORD,
                    ST::WILDCARD, ST::DATE, ST::DATE_NANOS, ST::IP, ST::BINARY, ST::COMPLETION, ST::TEXT,
                    ST::SEMANTIC, ST::WILDCARD},
                  {},
                  {JT::String}),
           BuildT(ST::UNSIGNED_LONG, {ST::UNSIGNED_LONG}, {}, {JT::Number}),
           BuildT(ST::COMPLETION,
                  {ST::COMPLETION, ST::KEYWORD, ST::MATCH_ONLY_TEXT, ST::CONSTANT_KEYWORD, ST::WILDCARD,
                    ST::DATE, ST::DATE_NANOS, ST::IP, ST::BINARY, ST::TEXT, ST::SEARCH_AS_YOU_TYPE,
                    ST::SEMANTIC, ST::WILDCARD},
                  {},
                  {JT::String}),
           BuildT(ST::SEARCH_AS_YOU_TYPE,
                   {ST::SEARCH_AS_YOU_TYPE, ST::KEYWORD, ST::MATCH_ONLY_TEXT, ST::CONSTANT_KEYWORD, ST::WILDCARD,
                    ST::DATE, ST::DATE_NANOS, ST::IP, ST::BINARY, ST::COMPLETION, ST::TEXT,
                    ST::SEMANTIC, ST::WILDCARD},
                  {},
                  {JT::String}),
           BuildT(ST::GEO_POINT, {ST::GEO_POINT}, {}, {JT::Object}),
           BuildT(ST::JOIN, {ST::JOIN}, {}, {JT::Object})),
    [](const testing::TestParamInfo<BuildValidation::ParamType>& info)
    {
        std::string name = schemf::typeToStr(std::get<0>(info.param));
        return name;
    });

} // namespace buildvalidationtest

namespace incompatibletypetest
{

class IncompatibleTypeTest : public Test
{
protected:
    std::shared_ptr<Schema> schema;
    const std::set<ST> INCOMPATIBLE_TYPES = {ST::KNN_VECTOR,
                                              ST::SPARSE_VECTOR,
                                              ST::RANK_FEATURE,
                                              ST::RANK_FEATURES,
                                              ST::PERCOLATOR,
                                              ST::STAR_TREE,
                                              ST::DERIVED,
                                              ST::INTEGER_RANGE,
                                              ST::LONG_RANGE,
                                              ST::FLOAT_RANGE,
                                              ST::DOUBLE_RANGE,
                                              ST::DATE_RANGE,
                                              ST::IP_RANGE};

    void SetUp() override
    {
        schema = std::make_shared<Schema>();
        for (auto stype : INCOMPATIBLE_TYPES)
        {
            schema->addField(getField(stype), Field(Field::Parameters {.type = stype}));
        }
    }

    std::shared_ptr<IValidator> getValidator() { return schema; }
};

TEST_F(IncompatibleTypeTest, IncompatibleTypesRejectAllJTypes)
{
    auto validator = getValidator();

    // Incompatible types should reject all JSON types
    for (auto incompatibleType : INCOMPATIBLE_TYPES)
    {
        auto target = getField(incompatibleType);
        for (auto jtype : ALLJTYPES)
        {
            auto valToken = JTypeToken::create(jtype);
            auto result = validator->validate(target, valToken);
            EXPECT_TRUE(base::isError(result))
                << fmt::format("Incompatible type {} should reject JSON type {}",
                               schemf::typeToStr(incompatibleType),
                               json::Json::typeToStr(jtype));
        }
    }
}

TEST_F(IncompatibleTypeTest, IncompatibleTypesOnlyAcceptThemselves)
{
    auto validator = getValidator();

    // Incompatible types should only accept their own type
    for (auto incompatibleType : INCOMPATIBLE_TYPES)
    {
        auto target = getField(incompatibleType);

        // TODO: check usage Should accept self
        auto selfToken = STypeToken::create(incompatibleType);
        auto selfResult = validator->validate(target, selfToken);
        EXPECT_FALSE(base::isError(selfResult))
            << fmt::format("Incompatible type {} should accept itself: {}",
                           schemf::typeToStr(incompatibleType),
                           base::getError(selfResult).message);

        // Should reject all other types
        for (auto otherType : ALLSCHEMATYPES)
        {
            if (otherType == incompatibleType)
                continue;

            auto valToken = STypeToken::create(otherType);
            auto result = validator->validate(target, valToken);
            EXPECT_TRUE(base::isError(result))
                << fmt::format("Incompatible type {} should reject schema type {}",
                               schemf::typeToStr(incompatibleType),
                               schemf::typeToStr(otherType));
        }
    }
}

} // namespace incompatibletypetest

