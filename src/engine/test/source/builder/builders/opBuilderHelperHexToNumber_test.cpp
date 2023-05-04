#include <any>
#include <gtest/gtest.h>
#include <vector>

#include <baseTypes.hpp>
#include <defs/failDef.hpp>

#include "opBuilderHelperMap.hpp"

using namespace base;
namespace bld = builder::internals::builders;

TEST(OpBuilderHelperHexToNumber, Builds)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+hex_to_number"},
                                 std::vector<std::string> {{"$ref"}},
                                 std::make_shared<defs::mocks::FailDef>());
    ASSERT_NO_THROW(std::apply(bld::opBuilderHelperHexToNumber, tuple));
}

TEST(OpBuilderHelperHexToNumber, WrongParametersSize)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+hex_to_number"},
                                 std::vector<std::string> {{"$ref"}, {"invalid"}},
                                 std::make_shared<defs::mocks::FailDef>());
    ASSERT_THROW(std::apply(bld::opBuilderHelperHexToNumber, tuple), std::runtime_error);

    tuple = std::make_tuple(std::string {"/field"},
                            std::string {"+hex_to_number"},
                            std::vector<std::string> {},
                            std::make_shared<defs::mocks::FailDef>());
    ASSERT_THROW(std::apply(bld::opBuilderHelperHexToNumber, tuple), std::runtime_error);
}

TEST(OpBuilderHelperHexToNumber, WrongParameterType)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+hex_to_number"},
                                 std::vector<std::string> {{"invalid"}},
                                 std::make_shared<defs::mocks::FailDef>());
    ASSERT_THROW(std::apply(bld::opBuilderHelperHexToNumber, tuple), std::runtime_error);
}

TEST(OpBuilderHelperHexToNumber, Success)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+hex_to_number"},
                                 std::vector<std::string> {{"$ref"}},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op = std::apply(bld::opBuilderHelperHexToNumber, tuple)->getPtr<Term<EngineOp>>()->getFn();
    auto event = std::make_shared<json::Json>(R"({
        "ref": "0x1234"
    })");
    auto result = op(event);
    ASSERT_TRUE(result);
    ASSERT_EQ(result.payload()->getInt("/field"), 4660);
}

TEST(OpBuilderHelperHexToNumber, FailureBadHex)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+hex_to_number"},
                                 std::vector<std::string> {{"$ref"}},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op = std::apply(bld::opBuilderHelperHexToNumber, tuple)->getPtr<Term<EngineOp>>()->getFn();
    auto event1 = std::make_shared<json::Json>(R"({
        "ref": "0tx1234g"
    })");
    auto event2 = std::make_shared<json::Json>(R"({
        "ref": "0Notx1234g"
    })");
    auto result = op(event1);
    ASSERT_FALSE(result);
    result = op(event2);
    ASSERT_FALSE(result);
}

TEST(OpBuilderHelperHexToNumber, FailureRefNotFound)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+hex_to_number"},
                                 std::vector<std::string> {{"$ref"}},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op = std::apply(bld::opBuilderHelperHexToNumber, tuple)->getPtr<Term<EngineOp>>()->getFn();
    auto event = std::make_shared<json::Json>(R"({
        "Notref": "0x1234"
    })");
    auto result = op(event);
    ASSERT_FALSE(result);
}

TEST(OpBuilderHelperHexToNumber, FailureRefNotString)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+hex_to_number"},
                                 std::vector<std::string> {{"$ref"}},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op = std::apply(bld::opBuilderHelperHexToNumber, tuple)->getPtr<Term<EngineOp>>()->getFn();
    auto event = std::make_shared<json::Json>(R"({
        "ref": 1234
    })");
    auto result = op(event);
    ASSERT_FALSE(result);
}
