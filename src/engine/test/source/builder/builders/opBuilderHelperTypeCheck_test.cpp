/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 */

#include <any>
#include <vector>

#include <gtest/gtest.h>

#include <baseTypes.hpp>

#include "opBuilderHelperFilter.hpp"

using namespace base;
using namespace builder::internals::builders;

const std::string targetField {"/check_field"};
const std::vector<std::string> arguments {};

TEST(opBuilderHelperTypeCheck, BuildIsNumber)
{
    const std::string helperFunctionName {"is_number"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    ASSERT_NO_THROW(opBuilderHelperIsNumber(tuple));
}

TEST(opBuilderHelperTypeCheck, BuildIsNotNumber)
{
    const std::string helperFunctionName {"is_not_number"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    ASSERT_NO_THROW(opBuilderHelperIsNotNumber(tuple));
}

TEST(opBuilderHelperTypeCheck, BuildIsString)
{
    const std::string helperFunctionName {"is_string"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    ASSERT_NO_THROW(opBuilderHelperIsString(tuple));
}

TEST(opBuilderHelperTypeCheck, BuildIsNotString)
{
    const std::string helperFunctionName {"is_not_string"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    ASSERT_NO_THROW(opBuilderHelperIsNotString(tuple));
}

TEST(opBuilderHelperTypeCheck, BuildIsBool)
{
    const std::string helperFunctionName {"is_boolean"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    ASSERT_NO_THROW(opBuilderHelperIsBool(tuple));
}

TEST(opBuilderHelperTypeCheck, BuildIsNotBool)
{
    const std::string helperFunctionName {"is_not_boolean"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    ASSERT_NO_THROW(opBuilderHelperIsNotBool(tuple));
}

TEST(opBuilderHelperTypeCheck, BuildIsArray)
{
    const std::string helperFunctionName {"is_array"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    ASSERT_NO_THROW(opBuilderHelperIsArray(tuple));
}

TEST(opBuilderHelperTypeCheck, BuildIsNotArray)
{
    const std::string helperFunctionName {"is_not_array"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    ASSERT_NO_THROW(opBuilderHelperIsNotArray(tuple));
}

TEST(opBuilderHelperTypeCheck, BuildIsObject)
{
    const std::string helperFunctionName {"is_object"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    ASSERT_NO_THROW(opBuilderHelperIsObject(tuple));
}

TEST(opBuilderHelperTypeCheck, BuildIsNotObject)
{
    const std::string helperFunctionName {"is_not_object"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    ASSERT_NO_THROW(opBuilderHelperIsNotObject(tuple));
}

TEST(opBuilderHelperTypeCheck, BuildIsNull)
{
    const std::string helperFunctionName {"is_null"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    ASSERT_NO_THROW(opBuilderHelperIsNull(tuple));
}

TEST(opBuilderHelperTypeCheck, BuildIsNotNull)
{
    const std::string helperFunctionName {"is_not_null"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    ASSERT_NO_THROW(opBuilderHelperIsNotNull(tuple));
}

TEST(opBuilderHelperTypeCheck, BuildIsTrue)
{
    const std::string helperFunctionName {"is_true"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    ASSERT_NO_THROW(opBuilderHelperIsTrue(tuple));
}

TEST(opBuilderHelperTypeCheck, IsFalseIsFalse)
{
    const std::string helperFunctionName {"is_faslse"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    ASSERT_NO_THROW(opBuilderHelperIsFalse(tuple));
}

// Check a String

TEST(opBuilderHelperTypeCheck, IsNumberCheckString)
{
    const std::string helperFunctionName {"is_number"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": "string"})");

    const auto op = opBuilderHelperIsNumber(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotNumberCheckString)
{
    const std::string helperFunctionName {"is_not_number"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": "string"})");

    const auto op = opBuilderHelperIsNotNumber(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsStringCheckString)
{
    const std::string helperFunctionName {"is_string"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": "string"})");

    const auto op = opBuilderHelperIsString(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotStringCheckString)
{
    const std::string helperFunctionName {"is_not_string"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": "string"})");

    const auto op = opBuilderHelperIsNotString(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsBoolCheckString)
{
    const std::string helperFunctionName {"is_boolean"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": "string"})");

    const auto op = opBuilderHelperIsBool(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotBoolCheckString)
{
    const std::string helperFunctionName {"is_not_boolean"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": "string"})");

    const auto op = opBuilderHelperIsNotBool(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsArrayCheckString)
{
    const std::string helperFunctionName {"is_array"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": "string"})");

    const auto op = opBuilderHelperIsArray(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotArrayCheckString)
{
    const std::string helperFunctionName {"is_not_array"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": "string"})");

    const auto op = opBuilderHelperIsNotArray(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsObjectCheckString)
{
    const std::string helperFunctionName {"is_object"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": "string"})");

    const auto op = opBuilderHelperIsObject(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotObjectCheckString)
{
    const std::string helperFunctionName {"is_not_object"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": "string"})");

    const auto op = opBuilderHelperIsNotObject(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNullCheckString)
{
    const std::string helperFunctionName {"is_null"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": "string"})");

    const auto op = opBuilderHelperIsNull(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotNullCheckString)
{
    const std::string helperFunctionName {"is_not_null"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": "string"})");

    const auto op = opBuilderHelperIsNotNull(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsTrueCheckString)
{
    const std::string helperFunctionName {"is_true"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": "string"})");

    const auto op = opBuilderHelperIsTrue(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsFalseCheckString)
{
    const std::string helperFunctionName {"is_false"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": "string"})");

    const auto op = opBuilderHelperIsFalse(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

// Check a Number

TEST(opBuilderHelperTypeCheck, IsNumberCheckNumber)
{
    const std::string helperFunctionName {"is_number"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": 1234.5678})");

    const auto op = opBuilderHelperIsNumber(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotNumberCheckNumber)
{
    const std::string helperFunctionName {"is_not_number"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": 1234.5678})");

    const auto op = opBuilderHelperIsNotNumber(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsStringCheckNumber)
{
    const std::string helperFunctionName {"is_string"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": 1234.5678})");

    const auto op = opBuilderHelperIsString(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotStringCheckNumber)
{
    const std::string helperFunctionName {"is_not_string"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": 1234.5678})");

    const auto op = opBuilderHelperIsNotString(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsBoolCheckNumber)
{
    const std::string helperFunctionName {"is_boolean"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": 1234.5678})");

    const auto op = opBuilderHelperIsBool(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotBoolCheckNumber)
{
    const std::string helperFunctionName {"is_not_boolean"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": 1234.5678})");

    const auto op = opBuilderHelperIsNotBool(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsArrayCheckNumber)
{
    const std::string helperFunctionName {"is_array"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": 1234.5678})");

    const auto op = opBuilderHelperIsArray(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotArrayCheckNumber)
{
    const std::string helperFunctionName {"is_not_array"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": 1234.5678})");

    const auto op = opBuilderHelperIsNotArray(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsObjectCheckNumber)
{
    const std::string helperFunctionName {"is_object"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": 1234.5678})");

    const auto op = opBuilderHelperIsObject(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotObjectCheckNumber)
{
    const std::string helperFunctionName {"is_not_object"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": 1234.5678})");

    const auto op = opBuilderHelperIsNotObject(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNullCheckNumber)
{
    const std::string helperFunctionName {"is_null"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": 1234.5678})");

    const auto op = opBuilderHelperIsNull(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotNullCheckNumber)
{
    const std::string helperFunctionName {"is_not_null"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": 1234.5678})");

    const auto op = opBuilderHelperIsNotNull(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsTrueCheckNumber)
{
    const std::string helperFunctionName {"is_true"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": 1234.5678})");

    const auto op = opBuilderHelperIsTrue(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsFalseCheckNumber)
{
    const std::string helperFunctionName {"is_false"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": 1234.5678})");

    const auto op = opBuilderHelperIsFalse(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

// Check a Bool

TEST(opBuilderHelperTypeCheck, IsNumberCheckBoolTrue)
{
    const std::string helperFunctionName {"is_number"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": true})");

    const auto op = opBuilderHelperIsNumber(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotNumberCheckBoolTrue)
{
    const std::string helperFunctionName {"is_not_number"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": true})");

    const auto op = opBuilderHelperIsNotNumber(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsStringCheckBoolTrue)
{
    const std::string helperFunctionName {"is_string"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": true})");

    const auto op = opBuilderHelperIsString(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotStringCheckBoolTrue)
{
    const std::string helperFunctionName {"is_not_string"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": true})");

    const auto op = opBuilderHelperIsNotString(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsBoolCheckBoolTrue)
{
    const std::string helperFunctionName {"is_boolean"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": true})");

    const auto op = opBuilderHelperIsBool(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotBoolCheckBoolTrue)
{
    const std::string helperFunctionName {"is_not_boolean"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": true})");

    const auto op = opBuilderHelperIsNotBool(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsArrayCheckBoolTrue)
{
    const std::string helperFunctionName {"is_array"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": true})");

    const auto op = opBuilderHelperIsArray(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotArrayCheckBoolTrue)
{
    const std::string helperFunctionName {"is_not_array"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": true})");

    const auto op = opBuilderHelperIsNotArray(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsObjectCheckBoolTrue)
{
    const std::string helperFunctionName {"is_object"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": true})");

    const auto op = opBuilderHelperIsObject(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotObjectCheckBoolTrue)
{
    const std::string helperFunctionName {"is_not_object"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": true})");

    const auto op = opBuilderHelperIsNotObject(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNullCheckBoolTrue)
{
    const std::string helperFunctionName {"is_null"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": true})");

    const auto op = opBuilderHelperIsNull(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotNullCheckBoolTrue)
{
    const std::string helperFunctionName {"is_not_null"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": true})");

    const auto op = opBuilderHelperIsNotNull(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsTrueCheckBoolTrue)
{
    const std::string helperFunctionName {"is_true"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": true})");

    const auto op = opBuilderHelperIsTrue(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsFalseCheckBoolTrue)
{
    const std::string helperFunctionName {"is_false"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": true})");

    const auto op = opBuilderHelperIsFalse(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

// Check a Bool

TEST(opBuilderHelperTypeCheck, IsNumberCheckBoolFalse)
{
    const std::string helperFunctionName {"is_number"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": false})");

    const auto op = opBuilderHelperIsNumber(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotNumberCheckBoolFalse)
{
    const std::string helperFunctionName {"is_not_number"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": false})");

    const auto op = opBuilderHelperIsNotNumber(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsStringCheckBoolFalse)
{
    const std::string helperFunctionName {"is_string"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": false})");

    const auto op = opBuilderHelperIsString(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotStringCheckBoolFalse)
{
    const std::string helperFunctionName {"is_not_string"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": false})");

    const auto op = opBuilderHelperIsNotString(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsBoolCheckBoolFalse)
{
    const std::string helperFunctionName {"is_boolean"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": false})");

    const auto op = opBuilderHelperIsBool(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotBoolCheckBoolFalse)
{
    const std::string helperFunctionName {"is_not_boolean"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": false})");

    const auto op = opBuilderHelperIsNotBool(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsArrayCheckBoolFalse)
{
    const std::string helperFunctionName {"is_array"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": false})");

    const auto op = opBuilderHelperIsArray(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotArrayCheckBoolFalse)
{
    const std::string helperFunctionName {"is_not_array"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": false})");

    const auto op = opBuilderHelperIsNotArray(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsObjectCheckBoolFalse)
{
    const std::string helperFunctionName {"is_object"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": false})");

    const auto op = opBuilderHelperIsObject(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotObjectCheckBoolFalse)
{
    const std::string helperFunctionName {"is_not_object"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": false})");

    const auto op = opBuilderHelperIsNotObject(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNullCheckBoolFalse)
{
    const std::string helperFunctionName {"is_null"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": false})");

    const auto op = opBuilderHelperIsNull(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotNullCheckBoolFalse)
{
    const std::string helperFunctionName {"is_not_null"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": false})");

    const auto op = opBuilderHelperIsNotNull(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsTrueCheckBoolFalse)
{
    const std::string helperFunctionName {"is_true"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": false})");

    const auto op = opBuilderHelperIsTrue(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsFalseCheckBoolFalse)
{
    const std::string helperFunctionName {"is_false"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": false})");

    const auto op = opBuilderHelperIsFalse(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

// Check a Array

TEST(opBuilderHelperTypeCheck, IsNumberCheckArray)
{
    const std::string helperFunctionName {"is_number"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event =
        std::make_shared<json::Json>(R"({"check_field": [ 123, false, "dummy" ] })");

    const auto op = opBuilderHelperIsNumber(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotNumberCheckArray)
{
    const std::string helperFunctionName {"is_not_number"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event =
        std::make_shared<json::Json>(R"({"check_field": [ 123, false, "dummy" ] })");

    const auto op = opBuilderHelperIsNotNumber(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsStringCheckArray)
{
    const std::string helperFunctionName {"is_string"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event =
        std::make_shared<json::Json>(R"({"check_field": [ 123, false, "dummy" ] })");

    const auto op = opBuilderHelperIsString(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotStringCheckArray)
{
    const std::string helperFunctionName {"is_not_string"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event =
        std::make_shared<json::Json>(R"({"check_field": [ 123, false, "dummy" ] })");

    const auto op = opBuilderHelperIsNotString(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsBoolCheckArray)
{
    const std::string helperFunctionName {"is_boolean"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event =
        std::make_shared<json::Json>(R"({"check_field": [ 123, false, "dummy" ] })");

    const auto op = opBuilderHelperIsBool(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotBoolCheckArray)
{
    const std::string helperFunctionName {"is_not_boolean"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event =
        std::make_shared<json::Json>(R"({"check_field": [ 123, false, "dummy" ] })");

    const auto op = opBuilderHelperIsNotBool(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsArrayCheckArray)
{
    const std::string helperFunctionName {"is_array"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event =
        std::make_shared<json::Json>(R"({"check_field": [ 123, false, "dummy" ] })");

    const auto op = opBuilderHelperIsArray(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotArrayCheckArray)
{
    const std::string helperFunctionName {"is_not_array"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event =
        std::make_shared<json::Json>(R"({"check_field": [ 123, false, "dummy" ] })");

    const auto op = opBuilderHelperIsNotArray(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsObjectCheckArray)
{
    const std::string helperFunctionName {"is_object"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event =
        std::make_shared<json::Json>(R"({"check_field": [ 123, false, "dummy" ] })");

    const auto op = opBuilderHelperIsObject(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotObjectCheckArray)
{
    const std::string helperFunctionName {"is_not_object"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event =
        std::make_shared<json::Json>(R"({"check_field": [ 123, false, "dummy" ] })");

    const auto op = opBuilderHelperIsNotObject(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNullCheckArray)
{
    const std::string helperFunctionName {"is_null"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event =
        std::make_shared<json::Json>(R"({"check_field": [ 123, false, "dummy" ] })");

    const auto op = opBuilderHelperIsNull(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotNullCheckArray)
{
    const std::string helperFunctionName {"is_not_null"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event =
        std::make_shared<json::Json>(R"({"check_field": [ 123, false, "dummy" ] })");

    const auto op = opBuilderHelperIsNotNull(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsTrueCheckArray)
{
    const std::string helperFunctionName {"is_true"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event =
        std::make_shared<json::Json>(R"({"check_field": [ 123, false, "dummy" ]})");

    const auto op = opBuilderHelperIsTrue(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsFalseCheckArray)
{
    const std::string helperFunctionName {"is_false"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event =
        std::make_shared<json::Json>(R"({"check_field": [ 123, false, "dummy" ] })");

    const auto op = opBuilderHelperIsFalse(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

// Check a Object

TEST(opBuilderHelperTypeCheck, IsNumberCheckObject)
{
    const std::string helperFunctionName {"is_number"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event =
        std::make_shared<json::Json>(R"({"check_field": { "key": "value" }})");

    const auto op = opBuilderHelperIsNumber(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotNumberCheckObject)
{
    const std::string helperFunctionName {"is_not_number"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event =
        std::make_shared<json::Json>(R"({"check_field": { "key": "value" }})");

    const auto op = opBuilderHelperIsNotNumber(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsStringCheckObject)
{
    const std::string helperFunctionName {"is_string"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event =
        std::make_shared<json::Json>(R"({"check_field": { "key": "value" }})");

    const auto op = opBuilderHelperIsString(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotStringCheckObject)
{
    const std::string helperFunctionName {"is_not_string"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event =
        std::make_shared<json::Json>(R"({"check_field": { "key": "value" }})");

    const auto op = opBuilderHelperIsNotString(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsBoolCheckObject)
{
    const std::string helperFunctionName {"is_boolean"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event =
        std::make_shared<json::Json>(R"({"check_field": { "key": "value" }})");

    const auto op = opBuilderHelperIsBool(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotBoolCheckObject)
{
    const std::string helperFunctionName {"is_not_boolean"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event =
        std::make_shared<json::Json>(R"({"check_field": { "key": "value" }})");

    const auto op = opBuilderHelperIsNotBool(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsArrayCheckObject)
{
    const std::string helperFunctionName {"is_array"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event =
        std::make_shared<json::Json>(R"({"check_field": { "key": "value" }})");

    const auto op = opBuilderHelperIsArray(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotArrayCheckObject)
{
    const std::string helperFunctionName {"is_not_array"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event =
        std::make_shared<json::Json>(R"({"check_field": { "key": "value" }})");

    const auto op = opBuilderHelperIsNotArray(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsObjectCheckObject)
{
    const std::string helperFunctionName {"is_object"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event =
        std::make_shared<json::Json>(R"({"check_field": { "key": "value" }})");

    const auto op = opBuilderHelperIsObject(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotObjectCheckObject)
{
    const std::string helperFunctionName {"is_not_object"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event =
        std::make_shared<json::Json>(R"({"check_field": { "key": "value" }})");

    const auto op = opBuilderHelperIsNotObject(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNullCheckObject)
{
    const std::string helperFunctionName {"is_null"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event =
        std::make_shared<json::Json>(R"({"check_field": { "key": "value" }})");

    const auto op = opBuilderHelperIsNull(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotNullCheckObject)
{
    const std::string helperFunctionName {"is_not_null"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event =
        std::make_shared<json::Json>(R"({"check_field": { "key": "value" }})");

    const auto op = opBuilderHelperIsNotNull(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsTrueCheckObject)
{
    const std::string helperFunctionName {"is_true"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event =
        std::make_shared<json::Json>(R"({"check_field": { "key": "value" }})");

    const auto op = opBuilderHelperIsTrue(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsFalseCheckObject)
{
    const std::string helperFunctionName {"is_false"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event =
        std::make_shared<json::Json>(R"({"check_field": { "key": "value" }})");

    const auto op = opBuilderHelperIsFalse(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

// Check a Null

TEST(opBuilderHelperTypeCheck, IsNumberCheckNull)
{
    const std::string helperFunctionName {"is_number"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": null})");

    const auto op = opBuilderHelperIsNumber(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotNumberCheckNull)
{
    const std::string helperFunctionName {"is_not_number"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": null})");

    const auto op = opBuilderHelperIsNotNumber(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsStringCheckNull)
{
    const std::string helperFunctionName {"is_string"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": null})");

    const auto op = opBuilderHelperIsString(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotStringCheckNull)
{
    const std::string helperFunctionName {"is_not_string"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": null})");

    const auto op = opBuilderHelperIsNotString(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsBoolCheckNull)
{
    const std::string helperFunctionName {"is_boolean"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": null})");

    const auto op = opBuilderHelperIsBool(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotBoolCheckNull)
{
    const std::string helperFunctionName {"is_not_boolean"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": null})");

    const auto op = opBuilderHelperIsNotBool(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsArrayCheckNull)
{
    const std::string helperFunctionName {"is_array"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": null})");

    const auto op = opBuilderHelperIsArray(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotArrayCheckNull)
{
    const std::string helperFunctionName {"is_not_array"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": null})");

    const auto op = opBuilderHelperIsNotArray(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsObjectCheckNull)
{
    const std::string helperFunctionName {"is_object"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": null})");

    const auto op = opBuilderHelperIsObject(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotObjectCheckNull)
{
    const std::string helperFunctionName {"is_not_object"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": null})");

    const auto op = opBuilderHelperIsNotObject(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNullCheckNull)
{
    const std::string helperFunctionName {"is_null"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": null})");

    const auto op = opBuilderHelperIsNull(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotNullCheckNull)
{
    const std::string helperFunctionName {"is_not_null"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": null})");

    const auto op = opBuilderHelperIsNotNull(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsTrueCheckNull)
{
    const std::string helperFunctionName {"is_true"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": null})");

    const auto op = opBuilderHelperIsTrue(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsFalseCheckNull)
{
    const std::string helperFunctionName {"is_false"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"check_field": null})");

    const auto op = opBuilderHelperIsFalse(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

// Check a nonexistent field

TEST(opBuilderHelperTypeCheck, IsNumberCheckNonexistentField)
{
    const std::string helperFunctionName {"is_number"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"other_field": null})");

    const auto op = opBuilderHelperIsNumber(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotNumberCheckNonexistentField)
{
    const std::string helperFunctionName {"is_not_number"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"other_field": null})");

    const auto op = opBuilderHelperIsNotNumber(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsStringCheckNonexistentField)
{
    const std::string helperFunctionName {"is_string"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"other_field": null})");

    const auto op = opBuilderHelperIsString(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotStringCheckNonexistentField)
{
    const std::string helperFunctionName {"is_not_string"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"other_field": null})");

    const auto op = opBuilderHelperIsNotString(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsBoolCheckNonexistentField)
{
    const std::string helperFunctionName {"is_boolean"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"other_field": null})");

    const auto op = opBuilderHelperIsBool(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotBoolCheckNonexistentField)
{
    const std::string helperFunctionName {"is_not_boolean"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"other_field": null})");

    const auto op = opBuilderHelperIsNotBool(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsArrayCheckNonexistentField)
{
    const std::string helperFunctionName {"is_array"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"other_field": null})");

    const auto op = opBuilderHelperIsArray(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotArrayCheckNonexistentField)
{
    const std::string helperFunctionName {"is_not_array"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"other_field": null})");

    const auto op = opBuilderHelperIsNotArray(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsObjectCheckNonexistentField)
{
    const std::string helperFunctionName {"is_object"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"other_field": null})");

    const auto op = opBuilderHelperIsObject(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotObjectCheckNonexistentField)
{
    const std::string helperFunctionName {"is_not_object"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"other_field": null})");

    const auto op = opBuilderHelperIsNotObject(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNullCheckNonexistentField)
{
    const std::string helperFunctionName {"is_null"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"other_field": null})");

    const auto op = opBuilderHelperIsNull(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsNotNullCheckNonexistentField)
{
    const std::string helperFunctionName {"is_not_null"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"other_field": null})");

    const auto op = opBuilderHelperIsNotNull(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsTrueCheckNonexistentField)
{
    const std::string helperFunctionName {"is_true"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"other_field": null})");

    const auto op = opBuilderHelperIsTrue(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperTypeCheck, IsFalseCheckNonexistentField)
{
    const std::string helperFunctionName {"is_false"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    const auto event = std::make_shared<json::Json>(R"({"other_field": null})");

    const auto op = opBuilderHelperIsFalse(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}
