
#include <any>
#include <gtest/gtest.h>
#include <vector>

#include <baseTypes.hpp>
#include <defs/failDef.hpp>

#include "opBuilderSpeficHLP.hpp"

using namespace base;
namespace bld = builder::internals::builders;

// Parse Boolean
TEST(Parse_bool, Builds)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_bool"},
                                 std::vector<std::string> {"TEST"},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_NO_THROW(std::apply(bld::opBuilderSpecificHLPBoolParse, tuple));
}

TEST(Parse_bool, Builds_bad_parameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_bool"},
                                 std::vector<std::string> {"test", "TEST"},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_THROW(std::apply(bld::opBuilderSpecificHLPBoolParse, tuple), std::runtime_error);
}

TEST(Parse_bool, Builds_bad_parameters2)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_bool"},
                                 std::vector<std::string> {},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_THROW(std::apply(bld::opBuilderSpecificHLPBoolParse, tuple), std::runtime_error);
}

TEST(Parse_bool, Match_value)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_bool"},
                                 std::vector<std::string> {"true"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPBoolParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_TRUE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isBool("/field"));
    ASSERT_TRUE(result1.payload().get()->getBool("/field").value() == true);
}

TEST(Parse_bool, Match_fail)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_bool"},
                                 std::vector<std::string> {"invalidValue"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPBoolParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_FALSE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isString("/field"));
    ASSERT_TRUE(result1.payload().get()->getString("/field").value() == "test");
}

TEST(Parse_bool, Match_ref)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_bool"},
                                 std::vector<std::string> {"$field_ref"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPBoolParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(R"({"field": "test", "field_ref": "true"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_TRUE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isBool("/field"));
    ASSERT_TRUE(result1.payload().get()->getBool("/field").value() == true);
}

TEST(Parse_bool, Ref_not_found)
{
    auto tuple = std::make_tuple(std::string {"/field_dst"},
                                 std::string {"parse_bool"},
                                 std::vector<std::string> {"$field_ref"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPBoolParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_FALSE(result1);
    ASSERT_FALSE(result1.payload().get()->exists("/field_dst"));
    ASSERT_FALSE(result1.payload().get()->exists("/field_ref"));
}

// Parse bytes
TEST(Parse_byte, Builds)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_byte"},
                                 std::vector<std::string> {"TEST"},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_NO_THROW(std::apply(bld::opBuilderSpecificHLPByteParse, tuple));
}

TEST(Parse_byte, Builds_bad_parameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_byte"},
                                 std::vector<std::string> {"test", "TEST"},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_THROW(std::apply(bld::opBuilderSpecificHLPByteParse, tuple), std::runtime_error);
}

TEST(Parse_byte, Builds_bad_parameters2)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_byte"},
                                 std::vector<std::string> {},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_THROW(std::apply(bld::opBuilderSpecificHLPByteParse, tuple), std::runtime_error);
}

TEST(Parse_byte, Match_value)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_byte"},
                                 std::vector<std::string> {"-125"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPByteParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_TRUE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isInt("/field"));
    ASSERT_TRUE(result1.payload().get()->getInt("/field").value() == -125);
}

TEST(Parse_byte, Match_fail)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_byte"},
                                 std::vector<std::string> {"invalidValue"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPByteParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};
    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_FALSE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isString("/field"));
    ASSERT_TRUE(result1.payload().get()->getString("/field").value() == "test");
}

TEST(Parse_byte, Match_ref)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_byte"},
                                 std::vector<std::string> {"$field_ref"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPByteParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(R"({"field": "test", "field_ref": "-125"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_TRUE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isInt("/field"));
    ASSERT_TRUE(result1.payload().get()->getInt("/field").value() == -125);
}

TEST(Parse_byte, Ref_not_found)
{
    auto tuple = std::make_tuple(std::string {"/field_dst"},
                                 std::string {"parse_byte"},
                                 std::vector<std::string> {"$field_ref"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPByteParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_FALSE(result1);
    ASSERT_FALSE(result1.payload().get()->exists("/field_dst"));
    ASSERT_FALSE(result1.payload().get()->exists("/field_ref"));
}

// Parse long
TEST(Parse_long, Builds)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_long"},
                                 std::vector<std::string> {"TEST"},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_NO_THROW(std::apply(bld::opBuilderSpecificHLPLongParse, tuple));
}

TEST(Parse_long, Builds_bad_parameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_long"},
                                 std::vector<std::string> {"test", "TEST"},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_THROW(std::apply(bld::opBuilderSpecificHLPLongParse, tuple), std::runtime_error);
}

TEST(Parse_long, Builds_bad_parameters2)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_long"},
                                 std::vector<std::string> {},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_THROW(std::apply(bld::opBuilderSpecificHLPLongParse, tuple), std::runtime_error);
}

TEST(Parse_long, Match_value)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_long"},
                                 std::vector<std::string> {"-9223372036854775808"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPLongParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_TRUE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isInt64("/field"));
    int64_t valueMin = std::int64_t {std::numeric_limits<std::int64_t>::min()};
    ASSERT_TRUE(valueMin == result1.payload().get()->getInt64("/field").value());
}

TEST(Parse_long, Match_fail)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_long"},
                                 std::vector<std::string> {"invalidValue"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPLongParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};
    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_FALSE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isString("/field"));
    ASSERT_TRUE(result1.payload().get()->getString("/field").value() == "test");
}

TEST(Parse_long, Match_ref)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_long"},
                                 std::vector<std::string> {"$field_ref"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPLongParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(R"({"field": "test", "field_ref": "-9223372036854775808"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_TRUE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isInt64("/field"));
    int64_t valueMin = std::int64_t {std::numeric_limits<std::int64_t>::min()};
    ASSERT_TRUE(valueMin == result1.payload().get()->getInt64("/field").value());
}

TEST(Parse_long, Ref_not_found)
{
    auto tuple = std::make_tuple(std::string {"/field_dst"},
                                 std::string {"parse_long"},
                                 std::vector<std::string> {"$field_ref"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPLongParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_FALSE(result1);
    ASSERT_FALSE(result1.payload().get()->exists("/field_dst"));
    ASSERT_FALSE(result1.payload().get()->exists("/field_ref"));
}

// Parse float
TEST(Parse_float, Builds)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_float"},
                                 std::vector<std::string> {"TEST"},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_NO_THROW(std::apply(bld::opBuilderSpecificHLPFloatParse, tuple));
}

TEST(Parse_float, Builds_bad_parameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_float"},
                                 std::vector<std::string> {"test", "TEST"},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_THROW(std::apply(bld::opBuilderSpecificHLPFloatParse, tuple), std::runtime_error);
}

TEST(Parse_float, Builds_bad_parameters2)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_float"},
                                 std::vector<std::string> {},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_THROW(std::apply(bld::opBuilderSpecificHLPFloatParse, tuple), std::runtime_error);
}

TEST(Parse_float, Match_value)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_float"},
                                 std::vector<std::string> {"-1.797693133354187"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPFloatParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_TRUE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isDouble("/field"));
    auto jsonVal = result1.payload().get()->getDouble("/field").value();
    ASSERT_TRUE(jsonVal == -1.797693133354187);
}

TEST(Parse_float, Match_fail)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_float"},
                                 std::vector<std::string> {"invalidValue"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPFloatParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};
    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_FALSE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isString("/field"));
    ASSERT_TRUE(result1.payload().get()->getString("/field").value() == "test");
}

TEST(Parse_float, Match_ref)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_float"},
                                 std::vector<std::string> {"$field_ref"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPFloatParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(R"({"field": "test", "field_ref": "1.797693133354187"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_TRUE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isDouble("/field"));
    ASSERT_TRUE(result1.payload().get()->getDouble("/field").value() == 1.797693133354187);
}

TEST(Parse_float, Ref_not_found)
{
    auto tuple = std::make_tuple(std::string {"/field_dst"},
                                 std::string {"parse_float"},
                                 std::vector<std::string> {"$field_ref"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPFloatParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_FALSE(result1);
    ASSERT_FALSE(result1.payload().get()->exists("/field_dst"));
    ASSERT_FALSE(result1.payload().get()->exists("/field_ref"));
}

// Parse base64
TEST(parse_binary, Builds)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_binary"},
                                 std::vector<std::string> {"TEST"},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_NO_THROW(std::apply(bld::opBuilderSpecificHLPBinaryParse, tuple));
}

TEST(parse_binary, Builds_bad_parameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_binary"},
                                 std::vector<std::string> {"test", "TEST"},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_THROW(std::apply(bld::opBuilderSpecificHLPBinaryParse, tuple), std::runtime_error);
}

TEST(parse_binary, Builds_bad_parameters2)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_binary"},
                                 std::vector<std::string> {},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_THROW(std::apply(bld::opBuilderSpecificHLPBinaryParse, tuple), std::runtime_error);
}

TEST(parse_binary, Match_value)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_binary"},
                                 std::vector<std::string> {"dGVzdA=="},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPBinaryParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_TRUE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isString("/field"));
    ASSERT_TRUE(result1.payload().get()->getString("/field").value() == "dGVzdA==");
}

TEST(parse_binary, Match_fail)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_binary"},
                                 std::vector<std::string> {"invalid Value %^&*!@#$%"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPBinaryParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};
    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_FALSE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isString("/field"));
    ASSERT_TRUE(result1.payload().get()->getString("/field").value() == "test");
}

TEST(parse_binary, Match_ref)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_binary"},
                                 std::vector<std::string> {"$field_ref"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPBinaryParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(R"({"field": "test", "field_ref": "dGVzdA=="})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_TRUE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isString("/field"));
    ASSERT_TRUE(result1.payload().get()->getString("/field").value() == "dGVzdA==");
}

TEST(parse_binary, Ref_not_found)
{
    auto tuple = std::make_tuple(std::string {"/field_dst"},
                                 std::string {"parse_binary"},
                                 std::vector<std::string> {"$field_ref"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPBinaryParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_FALSE(result1);
    ASSERT_FALSE(result1.payload().get()->exists("/field_dst"));
    ASSERT_FALSE(result1.payload().get()->exists("/field_ref"));
}

// parse date
TEST(Parse_date, Build)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_date"},
                                 std::vector<std::string> {"2019-01-01", "%Y-%m-%d"},
                                 std::make_shared<defs::mocks::FailDef>());
    ASSERT_NO_THROW(std::apply(bld::opBuilderSpecificHLPDateParse, tuple));
}

TEST(Parse_date, Build_opt_param)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_date"},
                                 std::vector<std::string> {"2019-01-01", "%Y-%m-%d", "en_US.UTF-8"},
                                 std::make_shared<defs::mocks::FailDef>());
    ASSERT_NO_THROW(std::apply(bld::opBuilderSpecificHLPDateParse, tuple));
}

TEST(Parse_date, Build_bad_parameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_date"},
                                 std::vector<std::string> {"2019-01-01"},
                                 std::make_shared<defs::mocks::FailDef>());
    ASSERT_THROW(std::apply(bld::opBuilderSpecificHLPDateParse, tuple), std::runtime_error);
}

TEST(Parse_date, Build_bad_parameters2)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_date"},
                                 std::vector<std::string> {"2019-01-01", "%Y-%m-%d", "en_US.UTF-8", "test"},
                                 std::make_shared<defs::mocks::FailDef>());
    ASSERT_THROW(std::apply(bld::opBuilderSpecificHLPDateParse, tuple), std::runtime_error);
}

TEST(Parse_date, Match_value)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_date"},
                                 std::vector<std::string> {"2019-01-01", "%Y-%m-%d", "en_US.UTF-8"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPDateParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_TRUE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isString("/field"));
    auto expectedDate = result1.payload().get()->getString("/field").value();
    ASSERT_STREQ(expectedDate.c_str(), "2019-01-01T00:00:00.000Z");
}

TEST(Parse_date, Match_fail)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_date"},
                                 std::vector<std::string> {"invalidValue!@#$%", "%Y-%m-%d", "en_US.UTF-8"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPDateParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_FALSE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isString("/field"));
    ASSERT_STREQ(result1.payload().get()->getString("/field").value().c_str(), "test");
}

TEST(Parse_date, Match_ref)
{
    auto tuple = std::make_tuple(std::string {"/field_dst"},
                                 std::string {"parse_date"},
                                 std::vector<std::string> {"$field_ref", "%Y-%m-%d"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPDateParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(R"({"field_dst": "test", "field_ref": "2019-01-01"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_TRUE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field_dst"));
    ASSERT_TRUE(result1.payload().get()->isString("/field_dst"));
    auto expectedDate = result1.payload().get()->getString("/field_dst").value();
    ASSERT_STREQ(expectedDate.c_str(), "2019-01-01T00:00:00.000Z");
}

// parse ip
TEST(Parse_ip, Builds)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_ip"},
                                 std::vector<std::string> {"TEST"},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_NO_THROW(std::apply(bld::opBuilderSpecificHLPIPParse, tuple));
}

TEST(Parse_ip, Builds_bad_parameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_ip"},
                                 std::vector<std::string> {"test", "TEST"},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_THROW(std::apply(bld::opBuilderSpecificHLPIPParse, tuple), std::runtime_error);
}

TEST(Parse_ip, Builds_bad_parameters2)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_ip"},
                                 std::vector<std::string> {},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_THROW(std::apply(bld::opBuilderSpecificHLPIPParse, tuple), std::runtime_error);
}

TEST(Parse_ip, Match_value)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_ip"},
                                 std::vector<std::string> {"::1"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPIPParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};
    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_TRUE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isString("/field"));
    ASSERT_TRUE(result1.payload().get()->getString("/field").value() == "::1");
}

TEST(Parse_ip, Match_ref)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_ip"},
                                 std::vector<std::string> {"$field_ref"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPIPParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(R"({"field": "test", "field_ref": "192.168.3.1"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_TRUE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isString("/field"));
    ASSERT_TRUE(result1.payload().get()->getString("/field").value() == "192.168.3.1");
}

TEST(Parse_ip, Ref_not_found)
{
    auto tuple = std::make_tuple(std::string {"/field_dst"},
                                 std::string {"parse_ip"},
                                 std::vector<std::string> {"$field_ref"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPIPParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_FALSE(result1);
    ASSERT_FALSE(result1.payload().get()->exists("/field_dst"));
    ASSERT_FALSE(result1.payload().get()->exists("/field_ref"));
}

// parser uri
TEST(Parse_uri, Builds)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_uri"},
                                 std::vector<std::string> {"TEST"},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_NO_THROW(std::apply(bld::opBuilderSpecificHLPURIParse, tuple));
}

TEST(Parse_uri, Builds_bad_parameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_uri"},
                                 std::vector<std::string> {"test", "TEST"},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_THROW(std::apply(bld::opBuilderSpecificHLPURIParse, tuple), std::runtime_error);
}

TEST(Parse_uri, Builds_bad_parameters2)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_uri"},
                                 std::vector<std::string> {},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_THROW(std::apply(bld::opBuilderSpecificHLPURIParse, tuple), std::runtime_error);
}

TEST(Parse_uri, Match_value)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_uri"},
                                 std::vector<std::string> {"http://www.wazuh.com"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPURIParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};
    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_TRUE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isObject("/field"));
    auto expected = R"({"original":"http://www.wazuh.com/","scheme":"http","domain":"www.wazuh.com","path":"/"})";
    ASSERT_STREQ(result1.payload().get()->str("/field").value().c_str(), expected);
}

TEST(Parse_uri, Match_fail)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_uri"},
                                 std::vector<std::string> {"www_wazuh_com"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPURIParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};
    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_FALSE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isString("/field"));
    ASSERT_TRUE(result1.payload().get()->getString("/field").value() == "test");
}

TEST(Parse_uri, Match_ref)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_uri"},
                                 std::vector<std::string> {"$field_ref"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPURIParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(R"({"field": "test", "field_ref": "http://www.wazuh.com"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_TRUE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isObject("/field"));
    auto expected = R"({"original":"http://www.wazuh.com/","scheme":"http","domain":"www.wazuh.com","path":"/"})";
    ASSERT_STREQ(result1.payload().get()->str("/field").value().c_str(), expected);
}

TEST(Parse_uri, Ref_not_found)
{
    auto tuple = std::make_tuple(std::string {"/field_dst"},
                                 std::string {"parse_uri"},
                                 std::vector<std::string> {"$field_ref"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPURIParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_FALSE(result1);
    ASSERT_FALSE(result1.payload().get()->exists("/field_dst"));
    ASSERT_FALSE(result1.payload().get()->exists("/field_ref"));
}

// parser user_agent
TEST(parse_useragent, Builds)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_useragent"},
                                 std::vector<std::string> {"TEST"},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_NO_THROW(std::apply(bld::opBuilderSpecificHLPUserAgentParse, tuple));
}

TEST(parse_useragent, Builds_bad_parameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_useragent"},
                                 std::vector<std::string> {"test", "TEST"},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_THROW(std::apply(bld::opBuilderSpecificHLPUserAgentParse, tuple), std::runtime_error);
}

TEST(parse_useragent, Builds_bad_parameters2)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_useragent"},
                                 std::vector<std::string> {},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_THROW(std::apply(bld::opBuilderSpecificHLPUserAgentParse, tuple), std::runtime_error);
}

TEST(parse_useragent, Match_value)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_useragent"},
                                 std::vector<std::string> {"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, "
                                                           "like Gecko) Chrome/80.0.3987.149 Safari/537.36"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPUserAgentParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};
    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_TRUE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isObject("/field"));
    auto expected =
        R"({"user_agent":{"original":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36"}})";
    ASSERT_STREQ(result1.payload().get()->str("/field").value().c_str(), expected);
}

TEST(parse_useragent, Match_ref)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_useragent"},
                                 std::vector<std::string> {"$field_ref"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPUserAgentParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(
        R"({"field": "test", "field_ref": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_TRUE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isObject("/field"));
    auto expected =
        R"({"user_agent":{"original":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36"}})";
    ASSERT_STREQ(result1.payload().get()->str("/field").value().c_str(), expected);
}

TEST(parse_useragent, Ref_not_found)
{
    auto tuple = std::make_tuple(std::string {"/field_dst"},
                                 std::string {"parse_useragent"},
                                 std::vector<std::string> {"$field_ref"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPUserAgentParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_FALSE(result1);
    ASSERT_FALSE(result1.payload().get()->exists("/field_dst"));
    ASSERT_FALSE(result1.payload().get()->exists("/field_ref"));
}

// parser fqdn
TEST(Parse_fqdn, Builds)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_fqdn"},
                                 std::vector<std::string> {"TEST"},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_NO_THROW(std::apply(bld::opBuilderSpecificHLPFQDNParse, tuple));
}

TEST(Parse_fqdn, Builds_bad_parameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_fqdn"},
                                 std::vector<std::string> {"test", "TEST"},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_THROW(std::apply(bld::opBuilderSpecificHLPFQDNParse, tuple), std::runtime_error);
}

TEST(Parse_fqdn, Builds_bad_parameters2)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_fqdn"},
                                 std::vector<std::string> {},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_THROW(std::apply(bld::opBuilderSpecificHLPFQDNParse, tuple), std::runtime_error);
}

TEST(Parse_fqdn, Match_value)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_fqdn"},
                                 std::vector<std::string> {"www.wazuh.com"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPFQDNParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};
    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_TRUE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isString("/field"));
    auto expected = R"(www.wazuh.com)";
    ASSERT_STREQ(result1.payload().get()->getString("/field").value().c_str(), expected);
}

TEST(Parse_fqdn, Match_fail)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_fqdn"},
                                 std::vector<std::string> {"....."},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPFQDNParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};
    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_FALSE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isString("/field"));
    auto expected = R"(test)";
    ASSERT_STREQ(result1.payload().get()->getString("/field").value().c_str(), expected);
}

TEST(Parse_fqdn, Match_ref)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_fqdn"},
                                 std::vector<std::string> {"$field_ref"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPFQDNParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(R"({"field": "test", "field_ref": "www.wazuh.com"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_TRUE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isString("/field"));
    auto expected = R"(www.wazuh.com)";
    ASSERT_STREQ(result1.payload().get()->getString("/field").value().c_str(), expected);
}

TEST(Parse_fqdn, Ref_not_found)
{
    auto tuple = std::make_tuple(std::string {"/field_dst"},
                                 std::string {"parse_fqdn"},
                                 std::vector<std::string> {"$field_ref"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPFQDNParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_FALSE(result1);
    ASSERT_FALSE(result1.payload().get()->exists("/field_dst"));
    ASSERT_FALSE(result1.payload().get()->exists("/field_ref"));
}

// parser parse_file
TEST(parse_file, Builds)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_file"},
                                 std::vector<std::string> {"TEST"},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_NO_THROW(std::apply(bld::opBuilderSpecificHLPFilePathParse, tuple));
}

TEST(parse_file, Builds_bad_parameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_file"},
                                 std::vector<std::string> {"test", "TEST"},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_THROW(std::apply(bld::opBuilderSpecificHLPFilePathParse, tuple), std::runtime_error);
}

TEST(parse_file, Builds_bad_parameters2)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_file"},
                                 std::vector<std::string> {},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_THROW(std::apply(bld::opBuilderSpecificHLPFilePathParse, tuple), std::runtime_error);
}

TEST(parse_file, Match_value)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_file"},
                                 std::vector<std::string> {"C:\\Users\\test\\test.txt"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPFilePathParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};
    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_TRUE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isObject("/field"));
    auto expected = R"({"drive_letter":"C","path":"C:\\Users\\test","name":"test.txt","ext":"txt"})";
    ASSERT_STREQ(result1.payload().get()->str("/field").value().c_str(), expected);
}

TEST(parse_file, Match_ref)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_file"},
                                 std::vector<std::string> {"$field_ref"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPFilePathParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(R"({"field": "test", "field_ref": "C:\\Users\\test\\test.txt"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_TRUE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isObject("/field"));
    auto expected = R"({"drive_letter":"C","path":"C:\\Users\\test","name":"test.txt","ext":"txt"})";
    ASSERT_STREQ(result1.payload().get()->str("/field").value().c_str(), expected);
}

TEST(parse_file, Ref_not_found)
{
    auto tuple = std::make_tuple(std::string {"/field_dst"},
                                 std::string {"parse_file"},
                                 std::vector<std::string> {"$field_ref"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPFilePathParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_FALSE(result1);
    ASSERT_FALSE(result1.payload().get()->exists("/field_dst"));
    ASSERT_FALSE(result1.payload().get()->exists("/field_ref"));
}

// parser parse json

TEST(Parse_json, Builds)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_json"},
                                 std::vector<std::string> {"TEST"},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_NO_THROW(std::apply(bld::opBuilderSpecificHLPJSONParse, tuple));
}

TEST(Parse_json, Builds_bad_parameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_json"},
                                 std::vector<std::string> {"test", "TEST"},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_THROW(std::apply(bld::opBuilderSpecificHLPJSONParse, tuple), std::runtime_error);
}

TEST(Parse_json, Builds_bad_parameters2)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_json"},
                                 std::vector<std::string> {},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_THROW(std::apply(bld::opBuilderSpecificHLPJSONParse, tuple), std::runtime_error);
}

TEST(Parse_json, Match_value)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_json"},
                                 std::vector<std::string> {"{\"test\": \"test\"}"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPJSONParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};
    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_TRUE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isObject("/field"));
    auto expected = R"({"test":"test"})";
    ASSERT_STREQ(result1.payload().get()->str("/field").value().c_str(), expected);
}

TEST(Parse_json, Match_fail)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_json"},
                                 std::vector<std::string> {"{\"test\" 123 \"test\""},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPJSONParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};
    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_FALSE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isString("/field"));
    ASSERT_STREQ(result1.payload().get()->getString("/field").value().c_str(), "test");
}

TEST(Parse_json, Match_ref)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_json"},
                                 std::vector<std::string> {"$field_ref"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPJSONParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(R"({"field": "test", "field_ref": "{\"test\": \"test\"}"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_TRUE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isObject("/field"));
    auto expected = R"({"test":"test"})";
    ASSERT_STREQ(result1.payload().get()->str("/field").value().c_str(), expected);
}

TEST(Parse_json, Ref_not_found)
{
    auto tuple = std::make_tuple(std::string {"/field_dst"},
                                 std::string {"parse_json"},
                                 std::vector<std::string> {"$field_ref"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPJSONParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_FALSE(result1);
    ASSERT_FALSE(result1.payload().get()->exists("/field_dst"));
    ASSERT_FALSE(result1.payload().get()->exists("/field_ref"));
}

// parse xml
TEST(Parse_xml, Builds)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_xml"},
                                 std::vector<std::string> {"TEST"},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_NO_THROW(std::apply(bld::opBuilderSpecificHLPXMLParse, tuple));
}

// parse xml
TEST(Parse_xml, Builds_with_opt_params)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_xml"},
                                 std::vector<std::string> {"windows"},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_NO_THROW(std::apply(bld::opBuilderSpecificHLPXMLParse, tuple));
}

TEST(Parse_xml, Builds_bad_parameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_xml"},
                                 std::vector<std::string> {"test", "TEST", "test"},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_THROW(std::apply(bld::opBuilderSpecificHLPXMLParse, tuple), std::runtime_error);
}

TEST(Parse_xml, Builds_empty_parameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_xml"},
                                 std::vector<std::string> {"test"},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_NO_THROW(std::apply(bld::opBuilderSpecificHLPXMLParse, tuple));
}

TEST(Parse_xml, Match_value)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_xml"},
                                 std::vector<std::string> {"<test attr=\"123\">value</test>"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPXMLParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};
    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_TRUE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isObject("/field"));
    auto expected = R"({"test":{"#text":"value","@attr":"123"}})";
    ASSERT_STREQ(result1.payload().get()->str("/field").value().c_str(), expected);
}

TEST(Parse_xml, Match_fail)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_xml"},
                                 std::vector<std::string> {"<test attr=\"123\">value</test"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPXMLParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};
    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_FALSE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isString("/field"));
    ASSERT_STREQ(result1.payload().get()->getString("/field").value().c_str(), "test");
}

TEST(Parse_xml, Match_ref)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_xml"},
                                 std::vector<std::string> {"$field_ref"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPXMLParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(R"({"field": "test", "field_ref": "<test attr=\"123\">value</test>"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_TRUE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isObject("/field"));
    auto expected = R"({"test":{"#text":"value","@attr":"123"}})";
    ASSERT_STREQ(result1.payload().get()->str("/field").value().c_str(), expected);
}

TEST(Parse_xml, Ref_not_found)
{
    auto tuple = std::make_tuple(std::string {"/field_dst"},
                                 std::string {"parse_xml"},
                                 std::vector<std::string> {"$field_ref"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPXMLParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_FALSE(result1);
    ASSERT_FALSE(result1.payload().get()->exists("/field_dst"));
    ASSERT_FALSE(result1.payload().get()->exists("/field_ref"));
}

// parse csv
TEST(Parse_csv, Builds)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_csv"},
                                 std::vector<std::string> {"source", "field1", "field2"},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_NO_THROW(std::apply(bld::opBuilderSpecificHLPCSVParse, tuple));
}

TEST(Parse_csv, Builds_with_opt_params)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_csv"},
                                 std::vector<std::string> {"source", "field1", "field2", "field3"},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_NO_THROW(std::apply(bld::opBuilderSpecificHLPCSVParse, tuple));
}

TEST(Parse_csv, Builds_bad_parameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_csv"},
                                 std::vector<std::string> {"source"},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_THROW(std::apply(bld::opBuilderSpecificHLPCSVParse, tuple), std::runtime_error);
}

TEST(Parse_csv, Builds_bad_parameters2)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_csv"},
                                 std::vector<std::string> {},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_THROW(std::apply(bld::opBuilderSpecificHLPCSVParse, tuple), std::runtime_error);
}

TEST(Parse_csv, Match_value)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_csv"},
                                 std::vector<std::string> {"test,123", "field1", "field2"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPCSVParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};
    auto event1 {std::make_shared<json::Json>(R"({"field": false})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_TRUE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isObject("/field"));
    auto expected = R"({"field1":"test","field2":123})";
    ASSERT_STREQ(result1.payload().get()->str("/field").value().c_str(), expected);
}

TEST(Parse_csv, Match_ref)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_csv"},
                                 std::vector<std::string> {"$field_ref", "field1", "field2"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPCSVParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(R"({"field": false, "field_ref": "test,123"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_TRUE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isObject("/field"));
    auto expected = R"({"field1":"test","field2":123})";
    ASSERT_STREQ(result1.payload().get()->str("/field").value().c_str(), expected);
}

TEST(Parse_csv, Match_fail)
{
    auto tuple = std::make_tuple(std::string {"/fail_field"},
                                 std::string {"parse_csv"},
                                 std::vector<std::string> {"test 123 456", "field1", "field2"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPCSVParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(R"({"field": false})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_FALSE(result1) << result1.payload().get()->str();
    ASSERT_FALSE(result1.payload().get()->exists("/fail_field"));
}

TEST(Parse_csv, Ref_not_found)
{
    auto tuple = std::make_tuple(std::string {"/field_dst"},
                                 std::string {"parse_csv"},
                                 std::vector<std::string> {"$field_ref", "field1", "field2"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPCSVParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(R"({"field": false})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_FALSE(result1);
    ASSERT_FALSE(result1.payload().get()->exists("/field_dst"));
    ASSERT_FALSE(result1.payload().get()->exists("/field_ref"));
}

// parse key value
TEST(parse_key_value, Builds)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_key_value"},
                                 std::vector<std::string> {"test string map", " ", "=", "\"", "\\"},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_NO_THROW(std::apply(bld::opBuilderSpecificHLPKeyValueParse, tuple));
}

TEST(parse_key_value, Builds_bad_parameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_key_value"},
                                 std::vector<std::string> {"test", "TEST", "test"},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_THROW(std::apply(bld::opBuilderSpecificHLPKeyValueParse, tuple), std::runtime_error);
}

TEST(parse_key_value, Builds_bad_parameters2)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_key_value"},
                                 std::vector<std::string> {},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_THROW(std::apply(bld::opBuilderSpecificHLPKeyValueParse, tuple), std::runtime_error);
}

TEST(parse_key_value, Match_value)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_key_value"},
                                 std::vector<std::string> {"key1=value1 key2=\"value2\"", "=", " ", "\"", "\\"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPKeyValueParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};
    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_TRUE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isObject("/field"));
    auto expected = R"({"key1":"value1","key2":"value2"})";
    ASSERT_STREQ(result1.payload().get()->str("/field").value().c_str(), expected);
}

TEST(parse_key_value, Match_ref)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_key_value"},
                                 std::vector<std::string> {"$field_ref", "=", " ", "\"", "\\"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPKeyValueParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(R"({"field": "test", "field_ref": "key1=value1 key2=value2"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_TRUE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isObject("/field"));
    auto expected = R"({"key1":"value1","key2":"value2"})";
    ASSERT_STREQ(result1.payload().get()->str("/field").value().c_str(), expected);
}

TEST(parse_key_value, Match_fail)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_key_value"},
                                 std::vector<std::string> {"$field_ref", " ", "=", "\"", "\\"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPKeyValueParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(R"({"field": "test", "field_ref": "1234567890"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_FALSE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isString("/field"));
    ASSERT_STREQ(result1.payload().get()->getString("/field").value().c_str(), "test");
}

TEST(parse_key_value, Ref_not_found)
{
    auto tuple = std::make_tuple(std::string {"/field_dst"},
                                 std::string {"parse_key_value"},
                                 std::vector<std::string> {"$field_ref", " ", "=", "\"", "\\"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPKeyValueParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_FALSE(result1);
    ASSERT_FALSE(result1.payload().get()->exists("/field_dst"));
    ASSERT_FALSE(result1.payload().get()->exists("/field_ref"));
}

// parse quoted
TEST(Parse_quoted, Builds_wout)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_quoted"},
                                 std::vector<std::string> {"test string map"},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_NO_THROW(std::apply(bld::opBuilderSpecificHLPQuotedParse, tuple));
}

TEST(Parse_quoted, Builds_w_2params)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_quoted"},
                                 std::vector<std::string> {"test string map", "\"", "\\"},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_NO_THROW(std::apply(bld::opBuilderSpecificHLPQuotedParse, tuple));
}

TEST(Parse_quoted, Builds_bad_parameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_quoted"},
                                 std::vector<std::string> {"test", "TEST", "test"},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_THROW(std::apply(bld::opBuilderSpecificHLPQuotedParse, tuple), std::runtime_error);
}

TEST(Parse_quoted, Builds_bad_parameters2)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_quoted"},
                                 std::vector<std::string> {},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_THROW(std::apply(bld::opBuilderSpecificHLPQuotedParse, tuple), std::runtime_error);
}

TEST(Parse_quoted, Match_value)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_quoted"},
                                 std::vector<std::string> {R"(#test quoted string#)", "#"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPQuotedParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};
    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_TRUE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isString("/field"));
    auto expected = R"("test quoted string")";
    ASSERT_STREQ(result1.payload().get()->str("/field").value().c_str(), expected);
}

TEST(Parse_quoted, Match_ref)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_quoted"},
                                 std::vector<std::string> {"$field_ref", "#"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPQuotedParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};
    auto event1 {std::make_shared<json::Json>(R"({"field": "test", "field_ref": "#test quoted string#"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_TRUE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isString("/field"));
    auto expected = R"("test quoted string")";
    ASSERT_STREQ(result1.payload().get()->str("/field").value().c_str(), expected);
}

TEST(Parse_quoted, Match_fail)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_quoted"},
                                 std::vector<std::string> {"$field_ref", "#"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPQuotedParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};
    auto event1 {std::make_shared<json::Json>(R"({"field": "test", "field_ref": "1234567890"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_FALSE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isString("/field"));
    ASSERT_STREQ(result1.payload().get()->getString("/field").value().c_str(), "test");
}

TEST(Parse_quoted, Ref_not_found)
{
    auto tuple = std::make_tuple(std::string {"/field_dst"},
                                 std::string {"parse_quoted"},
                                 std::vector<std::string> {"$field_ref", "#"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPQuotedParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};
    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_FALSE(result1);
    ASSERT_FALSE(result1.payload().get()->exists("/field_dst"));
    ASSERT_FALSE(result1.payload().get()->exists("/field_ref"));
}

// parse between
TEST(Parse_between, Builds_ok)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_between"},
                                 std::vector<std::string> {"start value end", "start", "end"},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_NO_THROW(std::apply(bld::opBuilderSpecificHLPBetweenParse, tuple));
}

TEST(Parse_between, Builds_bad_parameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_between"},
                                 std::vector<std::string> {"test", "test"},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_THROW(std::apply(bld::opBuilderSpecificHLPBetweenParse, tuple), std::runtime_error);
}

TEST(Parse_between, Builds_bad_parameters2)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_between"},
                                 std::vector<std::string> {},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_THROW(std::apply(bld::opBuilderSpecificHLPBetweenParse, tuple), std::runtime_error);
}

TEST(Parse_between, Match_value)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_between"},
                                 std::vector<std::string> {"start value end", "start ", " end"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPBetweenParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};
    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_TRUE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isString("/field"));
    ASSERT_STREQ(result1.payload().get()->getString("/field").value().c_str(), "value");
}

TEST(Parse_between, Match_ref)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_between"},
                                 std::vector<std::string> {"$field_ref", "start ", " end"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPBetweenParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};
    auto event1 {std::make_shared<json::Json>(R"({"field": "test", "field_ref": "start value end"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_TRUE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isString("/field"));
    ASSERT_STREQ(result1.payload().get()->getString("/field").value().c_str(), "value");
}

TEST(Parse_between, Match_fail)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_between"},
                                 std::vector<std::string> {"$field_ref", "start ", " end"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPBetweenParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};
    auto event1 {std::make_shared<json::Json>(R"({"field": "test", "field_ref": "1234567890"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_FALSE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isString("/field"));
    ASSERT_STREQ(result1.payload().get()->getString("/field").value().c_str(), "test");
}

TEST(Parse_between, Ref_not_found)
{
    auto tuple = std::make_tuple(std::string {"/field_dst"},
                                 std::string {"parse_between"},
                                 std::vector<std::string> {"$field_ref", "start ", " end"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op {std::apply(bld::opBuilderSpecificHLPBetweenParse, tuple)->getPtr<Term<EngineOp>>()->getFn()};
    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_FALSE(result1);
    ASSERT_FALSE(result1.payload().get()->exists("/field_ref"));
}
