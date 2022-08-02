#include <any>
#include <gtest/gtest.h>
#include <vector>

#include <baseTypes.hpp>

#include "opBuilderHelperFilter.hpp"

using namespace base;
namespace bld = builder::internals::builders;

TEST(opBuilderHelperTypeCheck, BuildIsNumber)
{
    auto tuple = std::make_tuple(
        std::string {"/field"}, std::string {"is_number"}, std::vector<std::string> {});

    ASSERT_NO_THROW(bld::opBuilderHelperIsNumber(tuple));
}

TEST(opBuilderHelperTypeCheck, BuildIsNotNumber)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"is_not_number"},
                                 std::vector<std::string> {});

    ASSERT_NO_THROW(bld::opBuilderHelperIsNotNumber(tuple));
}

TEST(opBuilderHelperTypeCheck, BuildIsString)
{
    auto tuple = std::make_tuple(
        std::string {"/field"}, std::string {"is_string"}, std::vector<std::string> {});

    ASSERT_NO_THROW(bld::opBuilderHelperIsString(tuple));
}

TEST(opBuilderHelperTypeCheck, BuildIsNotString)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"is_not_string"},
                                 std::vector<std::string> {});

    ASSERT_NO_THROW(bld::opBuilderHelperIsNotString(tuple));
}

TEST(opBuilderHelperTypeCheck, BuildIsBool)
{
    auto tuple = std::make_tuple(
        std::string {"/field"}, std::string {"is_bool"}, std::vector<std::string> {});

    ASSERT_NO_THROW(bld::opBuilderHelperIsBool(tuple));
}

TEST(opBuilderHelperTypeCheck, BuildIsNotBool)
{
    auto tuple = std::make_tuple(
        std::string {"/field"}, std::string {"is_not_bool"}, std::vector<std::string> {});

    ASSERT_NO_THROW(bld::opBuilderHelperIsNotBool(tuple));
}

TEST(opBuilderHelperTypeCheck, BuildIsArray)
{
    auto tuple = std::make_tuple(
        std::string {"/field"}, std::string {"is_array"}, std::vector<std::string> {});

    ASSERT_NO_THROW(bld::opBuilderHelperIsArray(tuple));
}

TEST(opBuilderHelperTypeCheck, BuildIsNotArray)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"is_not_array"},
                                 std::vector<std::string> {});

    ASSERT_NO_THROW(bld::opBuilderHelperIsNotArray(tuple));
}

TEST(opBuilderHelperTypeCheck, BuildIsObject)
{
    auto tuple = std::make_tuple(
        std::string {"/field"}, std::string {"is_object"}, std::vector<std::string> {});

    ASSERT_NO_THROW(bld::opBuilderHelperIsObject(tuple));
}

TEST(opBuilderHelperTypeCheck, BuildIsNotObject)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"is_not_object"},
                                 std::vector<std::string> {});

    ASSERT_NO_THROW(bld::opBuilderHelperIsNotObject(tuple));
}

TEST(opBuilderHelperTypeCheck, BuildIsNull)
{
    auto tuple = std::make_tuple(
        std::string {"/field"}, std::string {"is_null"}, std::vector<std::string> {});

    ASSERT_NO_THROW(bld::opBuilderHelperIsNull(tuple));
}

TEST(opBuilderHelperTypeCheck, BuildIsNotNull)
{
    auto tuple = std::make_tuple(
        std::string {"/field"}, std::string {"is_not_null"}, std::vector<std::string> {});

    ASSERT_NO_THROW(bld::opBuilderHelperIsNotNull(tuple));
}

TEST(opBuilderHelperTypeCheck, BuildIsTrue)
{
    auto tuple = std::make_tuple(
        std::string {"/field"}, std::string {"is_true"}, std::vector<std::string> {});

    ASSERT_NO_THROW(bld::opBuilderHelperIsTrue(tuple));
}

TEST(opBuilderHelperTypeCheck, IsFalseIsFalse)
{
    auto tuple = std::make_tuple(
        std::string {"/field"}, std::string {"is_faslse"}, std::vector<std::string> {});

    ASSERT_NO_THROW(bld::opBuilderHelperIsFalse(tuple));
}

// Check a String

TEST(opBuilderHelperTypeCheck, IsNumberCheckString)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_number"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": "string"})");

    auto op = bld::opBuilderHelperIsNumber(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotNumberCheckString)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_not_number"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": "string"})");

    auto op = bld::opBuilderHelperIsNotNumber(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsStringCheckString)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_string"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": "string"})");

    auto op = bld::opBuilderHelperIsString(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotStringCheckString)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_not_string"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": "string"})");

    auto op = bld::opBuilderHelperIsNotString(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsBoolCheckString)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_bool"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": "string"})");

    auto op = bld::opBuilderHelperIsBool(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotBoolCheckString)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_not_bool"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": "string"})");

    auto op = bld::opBuilderHelperIsNotBool(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsArrayCheckString)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_array"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": "string"})");

    auto op = bld::opBuilderHelperIsArray(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotArrayCheckString)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_not_array"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": "string"})");

    auto op = bld::opBuilderHelperIsNotArray(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsObjectCheckString)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_object"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": "string"})");

    auto op = bld::opBuilderHelperIsObject(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotObjectCheckString)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_not_object"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": "string"})");

    auto op = bld::opBuilderHelperIsNotObject(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNullCheckString)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_null"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": "string"})");

    auto op = bld::opBuilderHelperIsNull(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotNullCheckString)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_not_null"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": "string"})");

    auto op = bld::opBuilderHelperIsNotNull(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsTrueCheckString)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_true"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": "string"})");

    auto op = bld::opBuilderHelperIsTrue(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsFalseCheckString)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_false"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": "string"})");

    auto op = bld::opBuilderHelperIsFalse(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

// Check a Number

TEST(opBuilderHelperTypeCheck, IsNumberCheckNumber)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_number"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": 1234.5678})");

    auto op = bld::opBuilderHelperIsNumber(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotNumberCheckNumber)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_not_number"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": 1234.5678})");

    auto op = bld::opBuilderHelperIsNotNumber(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsStringCheckNumber)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_string"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": 1234.5678})");

    auto op = bld::opBuilderHelperIsString(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotStringCheckNumber)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_not_string"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": 1234.5678})");

    auto op = bld::opBuilderHelperIsNotString(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsBoolCheckNumber)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_bool"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": 1234.5678})");

    auto op = bld::opBuilderHelperIsBool(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotBoolCheckNumber)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_not_bool"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": 1234.5678})");

    auto op = bld::opBuilderHelperIsNotBool(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsArrayCheckNumber)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_array"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": 1234.5678})");

    auto op = bld::opBuilderHelperIsArray(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotArrayCheckNumber)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_not_array"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": 1234.5678})");

    auto op = bld::opBuilderHelperIsNotArray(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsObjectCheckNumber)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_object"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": 1234.5678})");

    auto op = bld::opBuilderHelperIsObject(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotObjectCheckNumber)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_not_object"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": 1234.5678})");

    auto op = bld::opBuilderHelperIsNotObject(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNullCheckNumber)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_null"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": 1234.5678})");

    auto op = bld::opBuilderHelperIsNull(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotNullCheckNumber)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_not_null"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": 1234.5678})");

    auto op = bld::opBuilderHelperIsNotNull(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsTrueCheckNumber)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_true"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": 1234.5678})");

    auto op = bld::opBuilderHelperIsTrue(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsFalseCheckNumber)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_false"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": 1234.5678})");

    auto op = bld::opBuilderHelperIsFalse(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

// Check a Bool

TEST(opBuilderHelperTypeCheck, IsNumberCheckBoolTrue)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_number"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": true})");

    auto op = bld::opBuilderHelperIsNumber(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotNumberCheckBoolTrue)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_not_number"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": true})");

    auto op = bld::opBuilderHelperIsNotNumber(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsStringCheckBoolTrue)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_string"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": true})");

    auto op = bld::opBuilderHelperIsString(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotStringCheckBoolTrue)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_not_string"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": true})");

    auto op = bld::opBuilderHelperIsNotString(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsBoolCheckBoolTrue)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_bool"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": true})");

    auto op = bld::opBuilderHelperIsBool(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotBoolCheckBoolTrue)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_not_bool"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": true})");

    auto op = bld::opBuilderHelperIsNotBool(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsArrayCheckBoolTrue)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_array"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": true})");

    auto op = bld::opBuilderHelperIsArray(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotArrayCheckBoolTrue)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_not_array"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": true})");

    auto op = bld::opBuilderHelperIsNotArray(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsObjectCheckBoolTrue)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_object"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": true})");

    auto op = bld::opBuilderHelperIsObject(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotObjectCheckBoolTrue)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_not_object"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": true})");

    auto op = bld::opBuilderHelperIsNotObject(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNullCheckBoolTrue)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_null"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": true})");

    auto op = bld::opBuilderHelperIsNull(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotNullCheckBoolTrue)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_not_null"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": true})");

    auto op = bld::opBuilderHelperIsNotNull(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsTrueCheckBoolTrue)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_true"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": true})");

    auto op = bld::opBuilderHelperIsTrue(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsFalseCheckBoolTrue)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_false"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": true})");

    auto op = bld::opBuilderHelperIsFalse(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

// Check a Bool

TEST(opBuilderHelperTypeCheck, IsNumberCheckBoolFalse)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_number"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": false})");

    auto op = bld::opBuilderHelperIsNumber(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotNumberCheckBoolFalse)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_not_number"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": false})");

    auto op = bld::opBuilderHelperIsNotNumber(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsStringCheckBoolFalse)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_string"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": false})");

    auto op = bld::opBuilderHelperIsString(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotStringCheckBoolFalse)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_not_string"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": false})");

    auto op = bld::opBuilderHelperIsNotString(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsBoolCheckBoolFalse)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_bool"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": false})");

    auto op = bld::opBuilderHelperIsBool(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotBoolCheckBoolFalse)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_not_bool"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": false})");

    auto op = bld::opBuilderHelperIsNotBool(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsArrayCheckBoolFalse)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_array"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": false})");

    auto op = bld::opBuilderHelperIsArray(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotArrayCheckBoolFalse)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_not_array"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": false})");

    auto op = bld::opBuilderHelperIsNotArray(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsObjectCheckBoolFalse)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_object"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": false})");

    auto op = bld::opBuilderHelperIsObject(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotObjectCheckBoolFalse)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_not_object"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": false})");

    auto op = bld::opBuilderHelperIsNotObject(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNullCheckBoolFalse)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_null"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": false})");

    auto op = bld::opBuilderHelperIsNull(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotNullCheckBoolFalse)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_not_null"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": false})");

    auto op = bld::opBuilderHelperIsNotNull(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsTrueCheckBoolFalse)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_true"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": false})");

    auto op = bld::opBuilderHelperIsTrue(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsFalseCheckBoolFalse)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_false"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": false})");

    auto op = bld::opBuilderHelperIsFalse(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

// Check a Array

TEST(opBuilderHelperTypeCheck, IsNumberCheckArray)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_number"},
                                 std::vector<std::string> {});

    auto event =
        std::make_shared<json::Json>(R"({"fieldcheck": [ 123, false, "dummy" ] })");

    auto op = bld::opBuilderHelperIsNumber(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotNumberCheckArray)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_not_number"},
                                 std::vector<std::string> {});

    auto event =
        std::make_shared<json::Json>(R"({"fieldcheck": [ 123, false, "dummy" ] })");

    auto op = bld::opBuilderHelperIsNotNumber(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsStringCheckArray)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_string"},
                                 std::vector<std::string> {});

    auto event =
        std::make_shared<json::Json>(R"({"fieldcheck": [ 123, false, "dummy" ] })");

    auto op = bld::opBuilderHelperIsString(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotStringCheckArray)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_not_string"},
                                 std::vector<std::string> {});

    auto event =
        std::make_shared<json::Json>(R"({"fieldcheck": [ 123, false, "dummy" ] })");

    auto op = bld::opBuilderHelperIsNotString(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsBoolCheckArray)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_bool"},
                                 std::vector<std::string> {});

    auto event =
        std::make_shared<json::Json>(R"({"fieldcheck": [ 123, false, "dummy" ] })");

    auto op = bld::opBuilderHelperIsBool(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotBoolCheckArray)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_not_bool"},
                                 std::vector<std::string> {});

    auto event =
        std::make_shared<json::Json>(R"({"fieldcheck": [ 123, false, "dummy" ] })");

    auto op = bld::opBuilderHelperIsNotBool(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsArrayCheckArray)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_array"},
                                 std::vector<std::string> {});

    auto event =
        std::make_shared<json::Json>(R"({"fieldcheck": [ 123, false, "dummy" ] })");

    auto op = bld::opBuilderHelperIsArray(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotArrayCheckArray)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_not_array"},
                                 std::vector<std::string> {});

    auto event =
        std::make_shared<json::Json>(R"({"fieldcheck": [ 123, false, "dummy" ] })");

    auto op = bld::opBuilderHelperIsNotArray(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsObjectCheckArray)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_object"},
                                 std::vector<std::string> {});

    auto event =
        std::make_shared<json::Json>(R"({"fieldcheck": [ 123, false, "dummy" ] })");

    auto op = bld::opBuilderHelperIsObject(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotObjectCheckArray)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_not_object"},
                                 std::vector<std::string> {});

    auto event =
        std::make_shared<json::Json>(R"({"fieldcheck": [ 123, false, "dummy" ] })");

    auto op = bld::opBuilderHelperIsNotObject(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNullCheckArray)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_null"},
                                 std::vector<std::string> {});

    auto event =
        std::make_shared<json::Json>(R"({"fieldcheck": [ 123, false, "dummy" ] })");

    auto op = bld::opBuilderHelperIsNull(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotNullCheckArray)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_not_null"},
                                 std::vector<std::string> {});

    auto event =
        std::make_shared<json::Json>(R"({"fieldcheck": [ 123, false, "dummy" ] })");

    auto op = bld::opBuilderHelperIsNotNull(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsTrueCheckArray)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_true"},
                                 std::vector<std::string> {});

    auto event =
        std::make_shared<json::Json>(R"({"fieldcheck": [ 123, false, "dummy" ]})");

    auto op = bld::opBuilderHelperIsTrue(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsFalseCheckArray)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_false"},
                                 std::vector<std::string> {});

    auto event =
        std::make_shared<json::Json>(R"({"fieldcheck": [ 123, false, "dummy" ] })");

    auto op = bld::opBuilderHelperIsFalse(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

// Check a Object

TEST(opBuilderHelperTypeCheck, IsNumberCheckObject)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_number"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": { "key": "value" } })");

    auto op = bld::opBuilderHelperIsNumber(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotNumberCheckObject)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_not_number"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": { "key": "value" } })");

    auto op = bld::opBuilderHelperIsNotNumber(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsStringCheckObject)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_string"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": { "key": "value" } })");

    auto op = bld::opBuilderHelperIsString(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotStringCheckObject)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_not_string"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": { "key": "value" } })");

    auto op = bld::opBuilderHelperIsNotString(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsBoolCheckObject)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_bool"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": { "key": "value" } })");

    auto op = bld::opBuilderHelperIsBool(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotBoolCheckObject)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_not_bool"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": { "key": "value" } })");

    auto op = bld::opBuilderHelperIsNotBool(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsArrayCheckObject)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_array"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": { "key": "value" } })");

    auto op = bld::opBuilderHelperIsArray(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotArrayCheckObject)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_not_array"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": { "key": "value" } })");

    auto op = bld::opBuilderHelperIsNotArray(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsObjectCheckObject)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_object"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": { "key": "value" } })");

    auto op = bld::opBuilderHelperIsObject(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotObjectCheckObject)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_not_object"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": { "key": "value" } })");

    auto op = bld::opBuilderHelperIsNotObject(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNullCheckObject)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_null"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": { "key": "value" } })");

    auto op = bld::opBuilderHelperIsNull(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotNullCheckObject)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_not_null"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": { "key": "value" } })");

    auto op = bld::opBuilderHelperIsNotNull(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsTrueCheckObject)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_true"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": { "key": "value" }})");

    auto op = bld::opBuilderHelperIsTrue(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsFalseCheckObject)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_false"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": { "key": "value" } })");

    auto op = bld::opBuilderHelperIsFalse(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

// Check a Null

TEST(opBuilderHelperTypeCheck, IsNumberCheckNull)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_number"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": null})");

    auto op = bld::opBuilderHelperIsNumber(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotNumberCheckNull)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_not_number"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": null})");

    auto op = bld::opBuilderHelperIsNotNumber(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsStringCheckNull)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_string"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": null})");

    auto op = bld::opBuilderHelperIsString(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotStringCheckNull)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_not_string"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": null})");

    auto op = bld::opBuilderHelperIsNotString(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsBoolCheckNull)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_bool"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": null})");

    auto op = bld::opBuilderHelperIsBool(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotBoolCheckNull)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_not_bool"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": null})");

    auto op = bld::opBuilderHelperIsNotBool(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsArrayCheckNull)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_array"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": null})");

    auto op = bld::opBuilderHelperIsArray(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotArrayCheckNull)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_not_array"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": null})");

    auto op = bld::opBuilderHelperIsNotArray(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsObjectCheckNull)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_object"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": null})");

    auto op = bld::opBuilderHelperIsObject(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotObjectCheckNull)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_not_object"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": null})");

    auto op = bld::opBuilderHelperIsNotObject(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNullCheckNull)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_null"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": null})");

    auto op = bld::opBuilderHelperIsNull(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotNullCheckNull)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_not_null"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": null})");

    auto op = bld::opBuilderHelperIsNotNull(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsTrueCheckNull)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_true"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": null})");

    auto op = bld::opBuilderHelperIsTrue(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsFalseCheckNull)
{
    auto tuple = std::make_tuple(std::string {"/fieldcheck"},
                                 std::string {"is_false"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": null})");

    auto op = bld::opBuilderHelperIsFalse(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

// Check a nonexistent field

TEST(opBuilderHelperTypeCheck, IsNumberCheckNonexistentField)
{
    auto tuple = std::make_tuple(std::string {"/nonexistent_field"},
                                 std::string {"is_number"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": null})");

    auto op = bld::opBuilderHelperIsNumber(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotNumberCheckNonexistentField)
{
    auto tuple = std::make_tuple(std::string {"/nonexistent_field"},
                                 std::string {"is_not_number"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": null})");

    auto op = bld::opBuilderHelperIsNotNumber(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsStringCheckNonexistentField)
{
    auto tuple = std::make_tuple(std::string {"/nonexistent_field"},
                                 std::string {"is_string"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": null})");

    auto op = bld::opBuilderHelperIsString(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotStringCheckNonexistentField)
{
    auto tuple = std::make_tuple(std::string {"/nonexistent_field"},
                                 std::string {"is_not_string"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": null})");

    auto op = bld::opBuilderHelperIsNotString(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsBoolCheckNonexistentField)
{
    auto tuple = std::make_tuple(std::string {"/nonexistent_field"},
                                 std::string {"is_bool"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": null})");

    auto op = bld::opBuilderHelperIsBool(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotBoolCheckNonexistentField)
{
    auto tuple = std::make_tuple(std::string {"/nonexistent_field"},
                                 std::string {"is_not_bool"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": null})");

    auto op = bld::opBuilderHelperIsNotBool(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsArrayCheckNonexistentField)
{
    auto tuple = std::make_tuple(std::string {"/nonexistent_field"},
                                 std::string {"is_array"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": null})");

    auto op = bld::opBuilderHelperIsArray(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotArrayCheckNonexistentField)
{
    auto tuple = std::make_tuple(std::string {"/nonexistent_field"},
                                 std::string {"is_not_array"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": null})");

    auto op = bld::opBuilderHelperIsNotArray(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsObjectCheckNonexistentField)
{
    auto tuple = std::make_tuple(std::string {"/nonexistent_field"},
                                 std::string {"is_object"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": null})");

    auto op = bld::opBuilderHelperIsObject(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotObjectCheckNonexistentField)
{
    auto tuple = std::make_tuple(std::string {"/nonexistent_field"},
                                 std::string {"is_not_object"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": null})");

    auto op = bld::opBuilderHelperIsNotObject(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNullCheckNonexistentField)
{
    auto tuple = std::make_tuple(std::string {"/nonexistent_field"},
                                 std::string {"is_null"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": null})");

    auto op = bld::opBuilderHelperIsNull(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotNullCheckNonexistentField)
{
    auto tuple = std::make_tuple(std::string {"/nonexistent_field"},
                                 std::string {"is_not_null"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": null})");

    auto op = bld::opBuilderHelperIsNotNull(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsTrueCheckNonexistentField)
{
    auto tuple = std::make_tuple(std::string {"/nonexistent_field"},
                                 std::string {"is_true"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": null})");

    auto op = bld::opBuilderHelperIsTrue(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsFalseCheckNonexistentField)
{
    auto tuple = std::make_tuple(std::string {"/nonexistent_field"},
                                 std::string {"is_false"},
                                 std::vector<std::string> {});

    auto event = std::make_shared<json::Json>(R"({"fieldcheck": null})");

    auto op = bld::opBuilderHelperIsFalse(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}
