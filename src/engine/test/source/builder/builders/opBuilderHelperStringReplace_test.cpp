/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 */

#include <any>
#include <vector>

#include <gtest/gtest.h>

#include <baseTypes.hpp>

#include "opBuilderHelperMap.hpp"

using namespace base;
using namespace builder::internals::builders;

const std::string helperFunctionName {"replace"};

const std::string targetField {"/field"};

TEST(opBuilderHelperStringReplace, build)
{
    const std::vector<std::string> arguments {"OldSubstr", "NewSubstr"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    ASSERT_NO_THROW(opBuilderHelperStringReplace(tuple));
}

TEST(opBuilderHelperStringReplace, buildNoTargetError)
{
    const std::vector<std::string> arguments {"OldSubstr", "NewSubstr"};
    const auto tuple = std::make_tuple("", helperFunctionName, arguments);

    ASSERT_THROW(opBuilderHelperStringReplace(tuple), std::runtime_error);
}

TEST(opBuilderHelperStringReplace, buildNoArgumentsError)
{
    const std::vector<std::string> arguments {};
    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    ASSERT_THROW(opBuilderHelperStringReplace(tuple), std::runtime_error);
}

TEST(opBuilderHelperStringReplace, buildInvalidParametersAmount)
{
    const std::vector<std::string> arguments {"only"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    ASSERT_THROW(opBuilderHelperStringReplace(tuple), std::runtime_error);
}

TEST(opBuilderHelperStringReplace, OldSubstrParameterEmpty)
{
    const std::vector<std::string> arguments {"", "NewSubstr"};

    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    ASSERT_THROW(opBuilderHelperStringReplace(tuple), std::runtime_error);
}

TEST(opBuilderHelperStringReplace, replaceCaseI)
{
    const std::vector<std::string> arguments {"OldSubstr", "NewSubstr"};
    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    auto event = std::make_shared<json::Json>(R"({"field": "Hi OldSubstr"})");

    auto op = opBuilderHelperStringReplace(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result);

    ASSERT_EQ("Hi NewSubstr", result.payload()->getString("/field").value());
}

TEST(opBuilderHelperStringReplace, replaceCaseII)
{
    const std::vector<std::string> arguments {"OldSubstr", "NewSubstr"};
    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    auto event = std::make_shared<json::Json>(R"({"field": "OldSubstr"})");

    auto op = opBuilderHelperStringReplace(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result);

    ASSERT_EQ("NewSubstr", result.payload()->getString("/field").value());
}

TEST(opBuilderHelperStringReplace, replaceCaseIII)
{
    const std::vector<std::string> arguments {"OldSubstr", "NewSubstr"};
    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    auto event = std::make_shared<json::Json>(R"({"field": "SomethingOldSubstrDummy"})");

    auto op = opBuilderHelperStringReplace(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result);

    ASSERT_EQ("SomethingNewSubstrDummy", result.payload()->getString("/field").value());
}

TEST(opBuilderHelperStringReplace, replaceCaseIV)
{
    const std::vector<std::string> arguments {"OldSubstr", "NewSubstr"};
    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    auto event = std::make_shared<json::Json>(
        R"({"field": "OldSubstrSomethingOldSubstrDummyOldSubstr"})");

    auto op = opBuilderHelperStringReplace(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result);

    ASSERT_EQ("NewSubstrSomethingNewSubstrDummyNewSubstr",
              result.payload()->getString("/field").value());
}

TEST(opBuilderHelperStringReplace, replaceCaseV)
{
    const std::vector<std::string> arguments {"OldSubstr", "NewSubstr"};
    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    auto event =
        std::make_shared<json::Json>(R"({"field": "OldSubstrOldSubstrOldSubstr"})");

    auto op = opBuilderHelperStringReplace(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result);

    ASSERT_EQ("NewSubstrNewSubstrNewSubstr",
              result.payload()->getString("/field").value());
}

TEST(opBuilderHelperStringReplace, replaceCaseVI)
{
    const std::vector<std::string> arguments {"OldSubstr", "NewSubstr"};
    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    auto event = std::make_shared<json::Json>(
        R"({"field": "Some dummy string that should remain the same"})");

    auto op = opBuilderHelperStringReplace(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result);

    ASSERT_EQ("Some dummy string that should remain the same",
              result.payload()->getString("/field").value());
}

TEST(opBuilderHelperStringReplace, replaceCaseVII)
{
    const std::vector<std::string> arguments {"OldSubstr", ""};
    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    auto event = std::make_shared<json::Json>(
        R"({"field": "Some string that contains an 'OldSubstr'."})");

    auto op = opBuilderHelperStringReplace(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result);

    ASSERT_EQ("Some string that contains an ''.",
              result.payload()->getString("/field").value());
}

TEST(opBuilderHelperStringReplace, replaceCaseVIII)
{
    const std::vector<std::string> arguments {"|", "?"};
    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    auto event = std::make_shared<json::Json>(
        R"({"field": "Some string that contains a symbol like '|'."})");

    auto op = opBuilderHelperStringReplace(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result);

    ASSERT_EQ("Some string that contains a symbol like '?'.",
              result.payload()->getString("/field").value());
}

TEST(opBuilderHelperStringReplace, replaceCaseIX)
{
    const std::vector<std::string> arguments {"|", "?"};
    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    auto event = std::make_shared<json::Json>(
        R"({"field": "Some string that contains a symbol like '|'."})");

    auto op = opBuilderHelperStringReplace(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result);

    ASSERT_EQ("Some string that contains a symbol like '?'.",
              result.payload()->getString("/field").value());
}

TEST(opBuilderHelperStringReplace, replaceCaseX)
{
    const std::vector<std::string> arguments {"|", "?"};
    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    auto event = std::make_shared<json::Json>(
        R"({"field": "|Some|| string that| contains many |symbols| |like '|'.|"})");

    auto op = opBuilderHelperStringReplace(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result);

    ASSERT_EQ("?Some?? string that? contains many ?symbols? ?like '?'.?",
              result.payload()->getString("/field").value());
}

TEST(opBuilderHelperStringReplace, replaceCaseXI)
{
    const std::vector<std::string> arguments {"|", ""};
    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    auto event = std::make_shared<json::Json>(
        R"({"field": "|Some|| string that| contains many |symbols| |like '|'.|"})");

    auto op = opBuilderHelperStringReplace(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result);

    ASSERT_EQ("Some string that contains many symbols like ''.",
              result.payload()->getString("/field").value());
}
