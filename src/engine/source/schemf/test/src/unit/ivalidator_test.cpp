#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <base/json.hpp>
#include <schemf/ivalidator.hpp>
#include <schemf/schema.hpp>

using namespace schemf;
using namespace testing;

// ---------------------------------------------------------------------------
// Token factories
// ---------------------------------------------------------------------------

TEST(IValidatorTest, JTypeToken_RejectsArrayType)
{
    EXPECT_THROW(JTypeToken::create(json::Json::Type::Array), std::invalid_argument);
}

TEST(IValidatorTest, JTypeToken_AcceptsNonArrayTypes)
{
    EXPECT_NO_THROW(JTypeToken::create(json::Json::Type::String));
    EXPECT_NO_THROW(JTypeToken::create(json::Json::Type::Number));
    EXPECT_NO_THROW(JTypeToken::create(json::Json::Type::Boolean));
    EXPECT_NO_THROW(JTypeToken::create(json::Json::Type::Object));
}

TEST(IValidatorTest, JTypeToken_IsJType)
{
    auto token = JTypeToken::create(json::Json::Type::String);
    EXPECT_TRUE(token->isJType());
    EXPECT_FALSE(token->isSType());
    EXPECT_FALSE(token->isValue());
    EXPECT_EQ(token->type(), json::Json::Type::String);
}

TEST(IValidatorTest, STypeToken_IsSType)
{
    auto token = STypeToken::create(Type::IP);
    EXPECT_TRUE(token->isSType());
    EXPECT_FALSE(token->isJType());
    EXPECT_FALSE(token->isValue());
    EXPECT_EQ(token->type(), Type::IP);
}

TEST(IValidatorTest, ValueToken_IsValue)
{
    json::Json val {"\"hello\""};
    auto token = ValueToken::create(val);
    EXPECT_TRUE(token->isValue());
    EXPECT_FALSE(token->isJType());
    EXPECT_FALSE(token->isSType());
}

TEST(IValidatorTest, BaseToken_NoneOfTheAbove)
{
    auto token = BaseToken::create();
    EXPECT_FALSE(token->isJType());
    EXPECT_FALSE(token->isSType());
    EXPECT_FALSE(token->isValue());
}

// ---------------------------------------------------------------------------
// runtimeValidation / elementValidationToken
// ---------------------------------------------------------------------------

TEST(IValidatorTest, RuntimeValidation_ReturnsNull)
{
    EXPECT_EQ(runtimeValidation(), nullptr);
}

TEST(IValidatorTest, ElementValidationToken_ReturnsNonNull)
{
    auto token = elementValidationToken();
    ASSERT_NE(token, nullptr);
    EXPECT_FALSE(token->isJType());
    EXPECT_FALSE(token->isSType());
    EXPECT_FALSE(token->isValue());
}

// ---------------------------------------------------------------------------
// ValidationResult
// ---------------------------------------------------------------------------

TEST(IValidatorTest, ValidationResult_NoValidatorMeansNoRuntime)
{
    ValidationResult vr;
    EXPECT_FALSE(vr.needsRuntimeValidation());
    EXPECT_EQ(vr.getValidator(), nullptr);
}

TEST(IValidatorTest, ValidationResult_WithValidatorNeedsRuntime)
{
    ValueValidator fn = [](const json::Json&) -> base::OptError
    {
        return base::noError();
    };
    ValidationResult vr(fn);
    EXPECT_TRUE(vr.needsRuntimeValidation());
    EXPECT_NE(vr.getValidator(), nullptr);
}

TEST(IValidatorTest, ValidationResult_ExplicitNull)
{
    ValidationResult vr(nullptr);
    EXPECT_FALSE(vr.needsRuntimeValidation());
}

// ---------------------------------------------------------------------------
// asArray
// ---------------------------------------------------------------------------

TEST(IValidatorTest, AsArray_NullPassthroughReturnsNull)
{
    ValueValidator wrapped = asArray(nullptr);
    EXPECT_EQ(wrapped, nullptr);
}

TEST(IValidatorTest, AsArray_ScalarDelegatesToInnerValidator)
{
    // Inner validator rejects non-strings
    ValueValidator inner = [](const json::Json& v) -> base::OptError
    {
        if (!v.isString())
            return base::Error {"not a string"};
        return base::noError();
    };

    ValueValidator wrapped = asArray(inner);
    ASSERT_NE(wrapped, nullptr);

    // Scalar string → pass
    EXPECT_FALSE(base::isError(wrapped(json::Json {"\"hello\""})));

    // Scalar number → fail
    auto res = wrapped(json::Json {"42"});
    ASSERT_TRUE(base::isError(res));
    EXPECT_THAT(base::getError(res).message, HasSubstr("not a string"));
}

TEST(IValidatorTest, AsArray_ValidArrayPassesAll)
{
    ValueValidator inner = [](const json::Json& v) -> base::OptError
    {
        if (!v.isString())
            return base::Error {"not a string"};
        return base::noError();
    };

    ValueValidator wrapped = asArray(inner);
    auto res = wrapped(json::Json {R"(["a","b","c"])"});
    EXPECT_FALSE(base::isError(res));
}

TEST(IValidatorTest, AsArray_ArrayWithInvalidItemFails)
{
    ValueValidator inner = [](const json::Json& v) -> base::OptError
    {
        if (!v.isString())
            return base::Error {"not a string"};
        return base::noError();
    };

    ValueValidator wrapped = asArray(inner);
    // Second element is a number
    auto res = wrapped(json::Json {R"(["a", 42, "c"])"});
    ASSERT_TRUE(base::isError(res));
    EXPECT_THAT(base::getError(res).message, HasSubstr("not a string"));
}

TEST(IValidatorTest, AsArray_EmptyArrayAlwaysPasses)
{
    ValueValidator inner = [](const json::Json&) -> base::OptError
    {
        return base::Error {"always fail"};
    };

    ValueValidator wrapped = asArray(inner);
    // Empty array — no elements to validate
    EXPECT_FALSE(base::isError(wrapped(json::Json {"[]"})));
}

// ---------------------------------------------------------------------------
// tokenFromReference
// ---------------------------------------------------------------------------

TEST(IValidatorTest, TokenFromReference_FieldExistsReturnsSTypeToken)
{
    Schema schema;
    schema.addField("a.b", Field::Parameters {.type = Type::IP});

    auto token = tokenFromReference(DotPath {"a.b"}, schema);
    ASSERT_NE(token, nullptr);
    EXPECT_TRUE(token->isSType());
    EXPECT_EQ(std::static_pointer_cast<STypeToken>(token)->type(), Type::IP);
}

TEST(IValidatorTest, TokenFromReference_MissingFieldReturnsNullptr)
{
    Schema schema;

    auto token = tokenFromReference(DotPath {"no.field"}, schema);
    EXPECT_EQ(token, nullptr);
}
