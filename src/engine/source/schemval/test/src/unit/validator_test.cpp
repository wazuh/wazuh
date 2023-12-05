#include <gtest/gtest.h>

#include <schemf/mockSchema.hpp>
#include <schemval/mockValidator.hpp> // Include mock to force compilation of the header.
#include <schemval/validator.hpp>
#include <test/behaviour.hpp>

using namespace base::test;

using SType = schemf::Type;
using JType = json::Json::Type;

using TableT = std::tuple<schemf::Type, json::Json::Type, bool>;
class TableTest : public ::testing::TestWithParam<TableT>
{
};

TEST_P(TableTest, SType)
{
    const auto& [type, jsonType, hasParser] = GetParam();

    schemval::Validator validator(std::make_shared<schemf::mocks::MockSchema>());
    ASSERT_EQ(validator.getJsonType(type), jsonType);
    if (hasParser)
    {
        // C++ does not allow to compare std::function, so we just check that it is not empty.
        ASSERT_NE(validator.getParser(type), nullptr) << "Parser for type " << schemf::typeToStr(type) << " is empty";
    }
    else
    {
        ASSERT_EQ(validator.getParser(type), nullptr)
            << "Parser for type " << schemf::typeToStr(type) << " is not empty";
    }
}

INSTANTIATE_TEST_SUITE_P(Validator,
                         TableTest,
                         testing::Values(TableT(SType::BOOLEAN, JType::Boolean, true),
                                         TableT(SType::BYTE, JType::Number, true),
                                         TableT(SType::SHORT, JType::Number, true),
                                         TableT(SType::INTEGER, JType::Number, true),
                                         TableT(SType::LONG, JType::Number, true),
                                         TableT(SType::FLOAT, JType::Number, true),
                                         TableT(SType::HALF_FLOAT, JType::Number, true),
                                         TableT(SType::SCALED_FLOAT, JType::Number, true),
                                         TableT(SType::DOUBLE, JType::Number, true),
                                         TableT(SType::KEYWORD, JType::String, true),
                                         TableT(SType::TEXT, JType::String, true),
                                         TableT(SType::DATE, JType::String, true),
                                         TableT(SType::DATE_NANOS, JType::String, true),
                                         TableT(SType::IP, JType::String, true),
                                         TableT(SType::BINARY, JType::String, true),
                                         TableT(SType::OBJECT, JType::Object, false),
                                         TableT(SType::NESTED, JType::Object, false)));

using IsCompT = std::tuple<schemf::Type, json::Json::Type>;
class IsCompatibleTest : public ::testing::TestWithParam<IsCompT>
{
};

std::vector<json::Json::Type> getRest(json::Json::Type exlcude)
{
    std::vector<json::Json::Type> ret;
    for (auto type : {JType::Boolean, JType::Number, JType::String, JType::Object, JType::Array})
    {
        if (type != exlcude)
        {
            ret.push_back(type);
        }
    }
    return ret;
}

TEST_P(IsCompatibleTest, STypeJType)
{
    const auto& [type, jsonType] = GetParam();

    schemval::Validator validator(std::make_shared<schemf::mocks::MockSchema>());
    // Success case
    ASSERT_TRUE(validator.isCompatible(type, jsonType));

    // Failure cases
    for (auto jType : getRest(jsonType))
    {
        ASSERT_FALSE(validator.isCompatible(type, jType));
    }
}

INSTANTIATE_TEST_SUITE_P(Validator,
                         IsCompatibleTest,
                         testing::Values(IsCompT(SType::BOOLEAN, JType::Boolean),
                                         IsCompT(SType::BYTE, JType::Number),
                                         IsCompT(SType::SHORT, JType::Number),
                                         IsCompT(SType::INTEGER, JType::Number),
                                         IsCompT(SType::LONG, JType::Number),
                                         IsCompT(SType::FLOAT, JType::Number),
                                         IsCompT(SType::HALF_FLOAT, JType::Number),
                                         IsCompT(SType::SCALED_FLOAT, JType::Number),
                                         IsCompT(SType::DOUBLE, JType::Number),
                                         IsCompT(SType::KEYWORD, JType::String),
                                         IsCompT(SType::TEXT, JType::String),
                                         IsCompT(SType::DATE, JType::String),
                                         IsCompT(SType::DATE_NANOS, JType::String),
                                         IsCompT(SType::IP, JType::String),
                                         IsCompT(SType::BINARY, JType::String),
                                         IsCompT(SType::OBJECT, JType::Object),
                                         IsCompT(SType::NESTED, JType::Array)));

namespace typevalidatetest
{
using SuccessExpected = InnerExpected<None, const std::shared_ptr<schemf::mocks::MockSchema>&>;
using FailureExpected = InnerExpected<None, const std::shared_ptr<schemf::mocks::MockSchema>&>;
using Expc = Expected<SuccessExpected, FailureExpected>;
auto Success = Expc::success();
auto Failure = Expc::failure();

using TypeValT = std::tuple<DotPath, json::Json::Type, Expc>;
class TypeValidateTest : public ::testing::TestWithParam<TypeValT>
{
};

TEST_P(TypeValidateTest, SType)
{
    const auto& [destPath, jType, expected] = GetParam();

    auto schema = std::make_shared<schemf::mocks::MockSchema>();
    schemval::Validator validator(schema);

    base::OptError err;
    if (expected)
    {
        expected.succCase()(schema);
        ASSERT_NO_THROW(err = validator.validate(destPath, jType));
        ASSERT_FALSE(err) << err.value().message;
    }
    else
    {
        expected.failCase()(schema);
        ASSERT_NO_THROW(err = validator.validate(destPath, jType));
        ASSERT_TRUE(err);
    }
}

using MockSchem = const std::shared_ptr<schemf::mocks::MockSchema>&;
INSTANTIATE_TEST_SUITE_P(
    Validator,
    TypeValidateTest,
    testing::Values(
        // Validation success
        TypeValT("field",
                 JType::Boolean,
                 Success(
                     [](MockSchem schema)
                     {
                         EXPECT_CALL(*schema, hasField(DotPath("field"))).WillOnce(testing::Return(true));
                         EXPECT_CALL(*schema, getType(DotPath("field"))).WillOnce(testing::Return(SType::BOOLEAN));
                         return None {};
                     })),
        // Validation failed
        TypeValT("field",
                 JType::Boolean,
                 Failure(
                     [](MockSchem schema)
                     {
                         EXPECT_CALL(*schema, hasField(DotPath("field"))).WillOnce(testing::Return(true));
                         EXPECT_CALL(*schema, getType(DotPath("field"))).WillOnce(testing::Return(SType::INTEGER));
                         return None {};
                     })),
        // Non Schema field
        TypeValT("field",
                 JType::Boolean,
                 Success(
                     [](MockSchem schema)
                     {
                         EXPECT_CALL(*schema, hasField(DotPath("field"))).WillOnce(testing::Return(false));
                         return None {};
                     }))));
} // namespace typevalidatetest

namespace refvalidatetest
{
using SuccessExpected = InnerExpected<None, const std::shared_ptr<schemf::mocks::MockSchema>&>;
using FailureExpected = InnerExpected<None, const std::shared_ptr<schemf::mocks::MockSchema>&>;
using Expc = Expected<SuccessExpected, FailureExpected>;

auto Success = Expc::success();
auto Failure = Expc::failure();

using RefValT = std::tuple<DotPath, DotPath, Expc>;
class RefValidateTest : public ::testing::TestWithParam<RefValT>
{
};

TEST_P(RefValidateTest, SType)
{
    const auto& [destPath, sourcePath, expected] = GetParam();

    auto schema = std::make_shared<schemf::mocks::MockSchema>();
    schemval::Validator validator(schema);

    base::OptError err;
    if (expected)
    {
        expected.succCase()(schema);
        ASSERT_NO_THROW(err = validator.validate(destPath, sourcePath));
        ASSERT_FALSE(err) << err.value().message;
    }
    else
    {
        expected.failCase()(schema);
        ASSERT_NO_THROW(err = validator.validate(destPath, sourcePath));
        ASSERT_TRUE(err);
    }
}

using MockSchem = const std::shared_ptr<schemf::mocks::MockSchema>&;
INSTANTIATE_TEST_SUITE_P(
    Validator,
    RefValidateTest,
    testing::Values(
        // Validation success
        RefValT("field1",
                "field2",
                Success(
                    [](MockSchem schema)
                    {
                        EXPECT_CALL(*schema, hasField(DotPath("field1"))).WillOnce(testing::Return(true));
                        EXPECT_CALL(*schema, getType(DotPath("field1"))).WillOnce(testing::Return(SType::BOOLEAN));
                        EXPECT_CALL(*schema, hasField(DotPath("field2"))).WillOnce(testing::Return(true));
                        EXPECT_CALL(*schema, getType(DotPath("field2"))).WillOnce(testing::Return(SType::BOOLEAN));
                        return None {};
                    })),
        // Validation failed
        RefValT("field1",
                "field2",
                Failure(
                    [](MockSchem schema)
                    {
                        EXPECT_CALL(*schema, hasField(DotPath("field1"))).WillOnce(testing::Return(true));
                        EXPECT_CALL(*schema, getType(DotPath("field1"))).WillOnce(testing::Return(SType::BOOLEAN));
                        EXPECT_CALL(*schema, hasField(DotPath("field2"))).WillOnce(testing::Return(true));
                        EXPECT_CALL(*schema, getType(DotPath("field2"))).WillOnce(testing::Return(SType::INTEGER));
                        return None {};
                    })),
        // Non Schema field1
        RefValT("field1",
                "field2",
                Success(
                    [](MockSchem schema)
                    {
                        EXPECT_CALL(*schema, hasField(DotPath("field1"))).WillOnce(testing::Return(false));
                        return None {};
                    })),
        // Non Schema field2
        RefValT("field1",
                "field2",
                Success(
                    [](MockSchem schema)
                    {
                        EXPECT_CALL(*schema, hasField(DotPath("field1"))).WillOnce(testing::Return(true));
                        EXPECT_CALL(*schema, hasField(DotPath("field2"))).WillOnce(testing::Return(false));
                        return None {};
                    }))));
} // namespace refvalidatetest
