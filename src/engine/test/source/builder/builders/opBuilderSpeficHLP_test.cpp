/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <any>
#include <gtest/gtest.h>
#include <vector>

#include <baseTypes.hpp>

#include "opBuilderSpeficHLP.hpp"

using namespace base;
namespace bld = builder::internals::builders;

// Parse Boolean
TEST(Parse_bool, Builds)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_bool"},
                                 std::vector<std::string> {"TEST"});

    ASSERT_NO_THROW(bld::opBuilderSpecificHLPBoolParse(tuple));
}

TEST(Parse_bool, Builds_bad_parameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_bool"},
                                 std::vector<std::string> {"test", "TEST"});

    ASSERT_THROW(bld::opBuilderSpecificHLPBoolParse(tuple), std::runtime_error);
}

TEST(Parse_bool, Builds_bad_parameters2)
{
    auto tuple = std::make_tuple(
        std::string {"/field"}, std::string {"parse_bool"}, std::vector<std::string> {});

    ASSERT_THROW(bld::opBuilderSpecificHLPBoolParse(tuple), std::runtime_error);
}

TEST(Parse_bool, Match_value)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_bool"},
                                 std::vector<std::string> {"true"});

    auto op {
        bld::opBuilderSpecificHLPBoolParse(tuple)->getPtr<Term<EngineOp>>()->getFn()};

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
                                 std::vector<std::string> {"invalidValue"});

    auto op {
        bld::opBuilderSpecificHLPBoolParse(tuple)->getPtr<Term<EngineOp>>()->getFn()};

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
                                 std::vector<std::string> {"$field_ref"});

    auto op {
        bld::opBuilderSpecificHLPBoolParse(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {
        std::make_shared<json::Json>(R"({"field": "test", "field_ref": "true"})")};

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
                                 std::vector<std::string> {"$field_ref"});

    auto op {
        bld::opBuilderSpecificHLPBoolParse(tuple)->getPtr<Term<EngineOp>>()->getFn()};

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
                                 std::vector<std::string> {"TEST"});

    ASSERT_NO_THROW(bld::opBuilderSpecificHLPByteParse(tuple));
}

TEST(Parse_byte, Builds_bad_parameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_byte"},
                                 std::vector<std::string> {"test", "TEST"});

    ASSERT_THROW(bld::opBuilderSpecificHLPByteParse(tuple), std::runtime_error);
}

TEST(Parse_byte, Builds_bad_parameters2)
{
    auto tuple = std::make_tuple(
        std::string {"/field"}, std::string {"parse_byte"}, std::vector<std::string> {});

    ASSERT_THROW(bld::opBuilderSpecificHLPByteParse(tuple), std::runtime_error);
}

TEST(Parse_byte, Match_value)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_byte"},
                                 std::vector<std::string> {"-125"});

    auto op {
        bld::opBuilderSpecificHLPByteParse(tuple)->getPtr<Term<EngineOp>>()->getFn()};

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
                                 std::vector<std::string> {"invalidValue"});

    auto op {
        bld::opBuilderSpecificHLPByteParse(tuple)->getPtr<Term<EngineOp>>()->getFn()};
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
                                 std::vector<std::string> {"$field_ref"});

    auto op {
        bld::opBuilderSpecificHLPByteParse(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {
        std::make_shared<json::Json>(R"({"field": "test", "field_ref": "-125"})")};

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
                                 std::vector<std::string> {"$field_ref"});

    auto op {
        bld::opBuilderSpecificHLPByteParse(tuple)->getPtr<Term<EngineOp>>()->getFn()};

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
                                 std::vector<std::string> {"TEST"});

    ASSERT_NO_THROW(bld::opBuilderSpecificHLPLongParse(tuple));
}

TEST(Parse_long, Builds_bad_parameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_long"},
                                 std::vector<std::string> {"test", "TEST"});

    ASSERT_THROW(bld::opBuilderSpecificHLPLongParse(tuple), std::runtime_error);
}

TEST(Parse_long, Builds_bad_parameters2)
{
    auto tuple = std::make_tuple(
        std::string {"/field"}, std::string {"parse_long"}, std::vector<std::string> {});

    ASSERT_THROW(bld::opBuilderSpecificHLPLongParse(tuple), std::runtime_error);
}

TEST(Parse_long, Match_value)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_long"},
                                 std::vector<std::string> {"-9223372036854775808"});

    auto op {
        bld::opBuilderSpecificHLPLongParse(tuple)->getPtr<Term<EngineOp>>()->getFn()};

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
                                 std::vector<std::string> {"invalidValue"});

    auto op {
        bld::opBuilderSpecificHLPLongParse(tuple)->getPtr<Term<EngineOp>>()->getFn()};
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
                                 std::vector<std::string> {"$field_ref"});

    auto op {
        bld::opBuilderSpecificHLPLongParse(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(
        R"({"field": "test", "field_ref": "-9223372036854775808"})")};

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
                                 std::vector<std::string> {"$field_ref"});

    auto op {
        bld::opBuilderSpecificHLPLongParse(tuple)->getPtr<Term<EngineOp>>()->getFn()};

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
                                 std::vector<std::string> {"TEST"});

    ASSERT_NO_THROW(bld::opBuilderSpecificHLPFloatParse(tuple));
}

TEST(Parse_float, Builds_bad_parameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_float"},
                                 std::vector<std::string> {"test", "TEST"});

    ASSERT_THROW(bld::opBuilderSpecificHLPFloatParse(tuple), std::runtime_error);
}

TEST(Parse_float, Builds_bad_parameters2)
{
    auto tuple = std::make_tuple(
        std::string {"/field"}, std::string {"parse_float"}, std::vector<std::string> {});

    ASSERT_THROW(bld::opBuilderSpecificHLPFloatParse(tuple), std::runtime_error);
}

TEST(Parse_float, Match_value)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_float"},
                                 std::vector<std::string> {"-1.797693133354187"});

    auto op {
        bld::opBuilderSpecificHLPFloatParse(tuple)->getPtr<Term<EngineOp>>()->getFn()};

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
                                 std::vector<std::string> {"invalidValue"});

    auto op {
        bld::opBuilderSpecificHLPFloatParse(tuple)->getPtr<Term<EngineOp>>()->getFn()};
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
                                 std::vector<std::string> {"$field_ref"});

    auto op {
        bld::opBuilderSpecificHLPFloatParse(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(
        R"({"field": "test", "field_ref": "1.797693133354187"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_TRUE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isDouble("/field"));
    ASSERT_TRUE(result1.payload().get()->getDouble("/field").value()
                == 1.797693133354187);
}

TEST(Parse_float, Ref_not_found)
{
    auto tuple = std::make_tuple(std::string {"/field_dst"},
                                 std::string {"parse_float"},
                                 std::vector<std::string> {"$field_ref"});

    auto op {
        bld::opBuilderSpecificHLPFloatParse(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_FALSE(result1);
    ASSERT_FALSE(result1.payload().get()->exists("/field_dst"));
    ASSERT_FALSE(result1.payload().get()->exists("/field_ref"));
}

// Parse base64
TEST(Parse_base64, Builds)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_base64"},
                                 std::vector<std::string> {"TEST"});

    ASSERT_NO_THROW(bld::opBuilderSpecificHLPBase64Parse(tuple));
}

TEST(Parse_base64, Builds_bad_parameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_base64"},
                                 std::vector<std::string> {"test", "TEST"});

    ASSERT_THROW(bld::opBuilderSpecificHLPBase64Parse(tuple), std::runtime_error);
}

TEST(Parse_base64, Builds_bad_parameters2)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_base64"},
                                 std::vector<std::string> {});

    ASSERT_THROW(bld::opBuilderSpecificHLPBase64Parse(tuple), std::runtime_error);
}

TEST(Parse_base64, Match_value)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_base64"},
                                 std::vector<std::string> {"dGVzdA=="});

    auto op {
        bld::opBuilderSpecificHLPBase64Parse(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_TRUE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isString("/field"));
    ASSERT_TRUE(result1.payload().get()->getString("/field").value() == "dGVzdA==");
}

TEST(Parse_base64, Match_fail)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_base64"},
                                 std::vector<std::string> {"invalid Value %^&*!@#$%"});

    auto op {
        bld::opBuilderSpecificHLPBase64Parse(tuple)->getPtr<Term<EngineOp>>()->getFn()};
    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_FALSE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isString("/field"));
    ASSERT_TRUE(result1.payload().get()->getString("/field").value() == "test");
}

TEST(Parse_base64, Match_ref)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_base64"},
                                 std::vector<std::string> {"$field_ref"});

    auto op {
        bld::opBuilderSpecificHLPBase64Parse(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {
        std::make_shared<json::Json>(R"({"field": "test", "field_ref": "dGVzdA=="})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_TRUE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isString("/field"));
    ASSERT_TRUE(result1.payload().get()->getString("/field").value() == "dGVzdA==");
}

TEST(Parse_base64, Ref_not_found)
{
    auto tuple = std::make_tuple(std::string {"/field_dst"},
                                 std::string {"parse_base64"},
                                 std::vector<std::string> {"$field_ref"});

    auto op {
        bld::opBuilderSpecificHLPBase64Parse(tuple)->getPtr<Term<EngineOp>>()->getFn()};

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
                                 std::vector<std::string> {"2019-01-01", "%Y-%m-%d"});
    ASSERT_NO_THROW(bld::opBuilderSpecificHLPDateParse(tuple));
}

TEST(Parse_date, Build_opt_param)
{
    auto tuple = std::make_tuple(
        std::string {"/field"},
        std::string {"parse_date"},
        std::vector<std::string> {"2019-01-01", "%Y-%m-%d", "en_US.UTF-8"});
    ASSERT_NO_THROW(bld::opBuilderSpecificHLPDateParse(tuple));
}

TEST(Parse_date, Build_bad_parameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_date"},
                                 std::vector<std::string> {"2019-01-01"});
    ASSERT_THROW(bld::opBuilderSpecificHLPDateParse(tuple), std::runtime_error);
}

TEST(Parse_date, Build_bad_parameters2)
{
    auto tuple = std::make_tuple(
        std::string {"/field"},
        std::string {"parse_date"},
        std::vector<std::string> {"2019-01-01", "%Y-%m-%d", "en_US.UTF-8", "test"});
    ASSERT_THROW(bld::opBuilderSpecificHLPDateParse(tuple), std::runtime_error);
}

TEST(Parse_date, Match_value)
{
    auto tuple = std::make_tuple(
        std::string {"/field"},
        std::string {"parse_date"},
        std::vector<std::string> {"2019-01-01", "%Y-%m-%d", "en_US.UTF-8"});

    auto op {
        bld::opBuilderSpecificHLPDateParse(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_TRUE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isString("/field"));
    auto expectedDate = result1.payload().get()->getString("/field").value();
    ASSERT_STREQ(expectedDate.c_str(), "2019-01-01T00:00:00.000Z");
}

TEST(Heler_HLP_parse_date, Match_fail)
{
    auto tuple = std::make_tuple(
        std::string {"/field"},
        std::string {"parse_date"},
        std::vector<std::string> {"invalidValue!@#$%", "%Y-%m-%d", "en_US.UTF-8"});

    auto op {
        bld::opBuilderSpecificHLPDateParse(tuple)->getPtr<Term<EngineOp>>()->getFn()};

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
                                 std::vector<std::string> {"$field_ref", "%Y-%m-%d"});

    auto op {
        bld::opBuilderSpecificHLPDateParse(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(
        R"({"field_dst": "test", "field_ref": "2019-01-01"})")};

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
                                 std::vector<std::string> {"TEST"});

    ASSERT_NO_THROW(bld::opBuilderSpecificHLPIPParse(tuple));
}

TEST(Parse_ip, Builds_bad_parameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_ip"},
                                 std::vector<std::string> {"test", "TEST"});

    ASSERT_THROW(bld::opBuilderSpecificHLPIPParse(tuple), std::runtime_error);
}

TEST(Parse_ip, Builds_bad_parameters2)
{
    auto tuple = std::make_tuple(
        std::string {"/field"}, std::string {"parse_ip"}, std::vector<std::string> {});

    ASSERT_THROW(bld::opBuilderSpecificHLPIPParse(tuple), std::runtime_error);
}

TEST(Parse_ip, Match_value)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_ip"},
                                 std::vector<std::string> {"::1"});

    auto op {bld::opBuilderSpecificHLPIPParse(tuple)->getPtr<Term<EngineOp>>()->getFn()};
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
                                 std::vector<std::string> {"$field_ref"});

    auto op {bld::opBuilderSpecificHLPIPParse(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {
        std::make_shared<json::Json>(R"({"field": "test", "field_ref": "192.168.3.1"})")};

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
                                 std::vector<std::string> {"$field_ref"});

    auto op {bld::opBuilderSpecificHLPIPParse(tuple)->getPtr<Term<EngineOp>>()->getFn()};

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
                                 std::vector<std::string> {"TEST"});

    ASSERT_NO_THROW(bld::opBuilderSpecificHLPURIParse(tuple));
}

TEST(Parse_uri, Builds_bad_parameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_uri"},
                                 std::vector<std::string> {"test", "TEST"});

    ASSERT_THROW(bld::opBuilderSpecificHLPURIParse(tuple), std::runtime_error);
}

TEST(Parse_uri, Builds_bad_parameters2)
{
    auto tuple = std::make_tuple(
        std::string {"/field"}, std::string {"parse_uri"}, std::vector<std::string> {});

    ASSERT_THROW(bld::opBuilderSpecificHLPURIParse(tuple), std::runtime_error);
}

TEST(Parse_uri, Match_value)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_uri"},
                                 std::vector<std::string> {"http://www.wazuh.com"});

    auto op {bld::opBuilderSpecificHLPURIParse(tuple)->getPtr<Term<EngineOp>>()->getFn()};
    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_TRUE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isString("/field"));
    ASSERT_TRUE(result1.payload().get()->getString("/field").value()
                == "http://www.wazuh.com");
}

TEST(Parse_uri, Match_fail)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_uri"},
                                 std::vector<std::string> {"www_wazuh_com"});

    auto op {bld::opBuilderSpecificHLPURIParse(tuple)->getPtr<Term<EngineOp>>()->getFn()};
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
                                 std::vector<std::string> {"$field_ref"});

    auto op {bld::opBuilderSpecificHLPURIParse(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(
        R"({"field": "test", "field_ref": "http://www.wazuh.com"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_TRUE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isString("/field"));
    ASSERT_TRUE(result1.payload().get()->getString("/field").value()
                == "http://www.wazuh.com");
}

TEST(Parse_uri, Ref_not_found)
{
    auto tuple = std::make_tuple(std::string {"/field_dst"},
                                 std::string {"parse_uri"},
                                 std::vector<std::string> {"$field_ref"});

    auto op {bld::opBuilderSpecificHLPURIParse(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_FALSE(result1);
    ASSERT_FALSE(result1.payload().get()->exists("/field_dst"));
    ASSERT_FALSE(result1.payload().get()->exists("/field_ref"));
}

// parser user_agent
TEST(Parse_user_agent, Builds)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_user_agent"},
                                 std::vector<std::string> {"TEST"});

    ASSERT_NO_THROW(bld::opBuilderSpecificHLPUserAgentParse(tuple));
}

TEST(Parse_user_agent, Builds_bad_parameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_user_agent"},
                                 std::vector<std::string> {"test", "TEST"});

    ASSERT_THROW(bld::opBuilderSpecificHLPUserAgentParse(tuple), std::runtime_error);
}

TEST(Parse_user_agent, Builds_bad_parameters2)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_user_agent"},
                                 std::vector<std::string> {});

    ASSERT_THROW(bld::opBuilderSpecificHLPUserAgentParse(tuple), std::runtime_error);
}

TEST(Parse_user_agent, Match_value)
{
    auto tuple =
        std::make_tuple(std::string {"/field"},
                        std::string {"parse_user_agent"},
                        std::vector<std::string> {
                            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, "
                            "like Gecko) Chrome/80.0.3987.149 Safari/537.36"});

    auto op {bld::opBuilderSpecificHLPUserAgentParse(tuple)
                 ->getPtr<Term<EngineOp>>()
                 ->getFn()};
    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_TRUE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isObject("/field"));
    auto expected =
        R"({"user_agent":{"original":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36"}})";
    ASSERT_STREQ(result1.payload().get()->str("/field").value().c_str(), expected);
}

TEST(Parse_user_agent, Match_ref)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_user_agent"},
                                 std::vector<std::string> {"$field_ref"});

    auto op {bld::opBuilderSpecificHLPUserAgentParse(tuple)
                 ->getPtr<Term<EngineOp>>()
                 ->getFn()};

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

TEST(Parse_user_agent, Ref_not_found)
{
    auto tuple = std::make_tuple(std::string {"/field_dst"},
                                 std::string {"parse_user_agent"},
                                 std::vector<std::string> {"$field_ref"});

    auto op {bld::opBuilderSpecificHLPUserAgentParse(tuple)
                 ->getPtr<Term<EngineOp>>()
                 ->getFn()};

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
                                 std::vector<std::string> {"TEST"});

    ASSERT_NO_THROW(bld::opBuilderSpecificHLPFQDNParse(tuple));
}

TEST(Parse_fqdn, Builds_bad_parameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_fqdn"},
                                 std::vector<std::string> {"test", "TEST"});

    ASSERT_THROW(bld::opBuilderSpecificHLPFQDNParse(tuple), std::runtime_error);
}

TEST(Parse_fqdn, Builds_bad_parameters2)
{
    auto tuple = std::make_tuple(
        std::string {"/field"}, std::string {"parse_fqdn"}, std::vector<std::string> {});

    ASSERT_THROW(bld::opBuilderSpecificHLPFQDNParse(tuple), std::runtime_error);
}

TEST(Parse_fqdn, Match_value)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_fqdn"},
                                 std::vector<std::string> {"www.wazuh.com"});

    auto op {
        bld::opBuilderSpecificHLPFQDNParse(tuple)->getPtr<Term<EngineOp>>()->getFn()};
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
                                 std::vector<std::string> {"....."});

    auto op {
        bld::opBuilderSpecificHLPFQDNParse(tuple)->getPtr<Term<EngineOp>>()->getFn()};
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
                                 std::vector<std::string> {"$field_ref"});

    auto op {
        bld::opBuilderSpecificHLPFQDNParse(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(
        R"({"field": "test", "field_ref": "www.wazuh.com"})")};

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
                                 std::vector<std::string> {"$field_ref"});

    auto op {
        bld::opBuilderSpecificHLPFQDNParse(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_FALSE(result1);
    ASSERT_FALSE(result1.payload().get()->exists("/field_dst"));
    ASSERT_FALSE(result1.payload().get()->exists("/field_ref"));
}

// parser parse_file_path
TEST(Parse_file_path, Builds)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_file_path"},
                                 std::vector<std::string> {"TEST"});

    ASSERT_NO_THROW(bld::opBuilderSpecificHLPFilePathParse(tuple));
}

TEST(Parse_file_path, Builds_bad_parameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_file_path"},
                                 std::vector<std::string> {"test", "TEST"});

    ASSERT_THROW(bld::opBuilderSpecificHLPFilePathParse(tuple), std::runtime_error);
}

TEST(Parse_file_path, Builds_bad_parameters2)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_file_path"},
                                 std::vector<std::string> {});

    ASSERT_THROW(bld::opBuilderSpecificHLPFilePathParse(tuple), std::runtime_error);
}

TEST(Parse_file_path, Match_value)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_file_path"},
                                 std::vector<std::string> {"C:\\Users\\test\\test.txt"});

    auto op {
        bld::opBuilderSpecificHLPFilePathParse(tuple)->getPtr<Term<EngineOp>>()->getFn()};
    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_TRUE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isObject("/field"));
    auto expected =
        R"({"drive_letter":"C","path":"C:\\Users\\test","name":"test.txt","ext":"txt"})";
    ASSERT_STREQ(result1.payload().get()->str("/field").value().c_str(), expected);
}

TEST(Parse_file_path, Match_ref)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_file_path"},
                                 std::vector<std::string> {"$field_ref"});

    auto op {
        bld::opBuilderSpecificHLPFilePathParse(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(
        R"({"field": "test", "field_ref": "C:\\Users\\test\\test.txt"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_TRUE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isObject("/field"));
    auto expected =
        R"({"drive_letter":"C","path":"C:\\Users\\test","name":"test.txt","ext":"txt"})";
    ASSERT_STREQ(result1.payload().get()->str("/field").value().c_str(), expected);
}

TEST(Parse_file_path, Ref_not_found)
{
    auto tuple = std::make_tuple(std::string {"/field_dst"},
                                 std::string {"parse_file_path"},
                                 std::vector<std::string> {"$field_ref"});

    auto op {
        bld::opBuilderSpecificHLPFilePathParse(tuple)->getPtr<Term<EngineOp>>()->getFn()};

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
                                 std::vector<std::string> {"TEST"});

    ASSERT_NO_THROW(bld::opBuilderSpecificHLPJSONParse(tuple));
}

TEST(Parse_json, Builds_bad_parameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_json"},
                                 std::vector<std::string> {"test", "TEST"});

    ASSERT_THROW(bld::opBuilderSpecificHLPJSONParse(tuple), std::runtime_error);
}

TEST(Parse_json, Builds_bad_parameters2)
{
    auto tuple = std::make_tuple(
        std::string {"/field"}, std::string {"parse_json"}, std::vector<std::string> {});

    ASSERT_THROW(bld::opBuilderSpecificHLPJSONParse(tuple), std::runtime_error);
}

TEST(Parse_json, Match_value)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_json"},
                                 std::vector<std::string> {"{\"test\": \"test\"}"});

    auto op {
        bld::opBuilderSpecificHLPJSONParse(tuple)->getPtr<Term<EngineOp>>()->getFn()};
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
                                 std::vector<std::string> {"{\"test\" 123 \"test\""});

    auto op {
        bld::opBuilderSpecificHLPJSONParse(tuple)->getPtr<Term<EngineOp>>()->getFn()};
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
                                 std::vector<std::string> {"$field_ref"});

    auto op {
        bld::opBuilderSpecificHLPJSONParse(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(
        R"({"field": "test", "field_ref": "{\"test\": \"test\"}"})")};

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
                                 std::vector<std::string> {"$field_ref"});

    auto op {
        bld::opBuilderSpecificHLPJSONParse(tuple)->getPtr<Term<EngineOp>>()->getFn()};

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
                                 std::vector<std::string> {"TEST"});

    ASSERT_NO_THROW(bld::opBuilderSpecificHLPXMLParse(tuple));
}

// parse xml
TEST(Parse_xml, Builds_with_opt_params)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_xml"},
                                 std::vector<std::string> {"TEST", "true"});

    ASSERT_NO_THROW(bld::opBuilderSpecificHLPXMLParse(tuple));
}

TEST(Parse_xml, Builds_bad_parameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_xml"},
                                 std::vector<std::string> {"test", "TEST", "test"});

    ASSERT_THROW(bld::opBuilderSpecificHLPXMLParse(tuple), std::runtime_error);
}

TEST(Parse_xml, Builds_bad_parameters2)
{
    auto tuple = std::make_tuple(
        std::string {"/field"}, std::string {"parse_xml"}, std::vector<std::string> {});

    ASSERT_THROW(bld::opBuilderSpecificHLPXMLParse(tuple), std::runtime_error);
}

TEST(Parse_xml, Match_value)
{
    auto tuple =
        std::make_tuple(std::string {"/field"},
                        std::string {"parse_xml"},
                        std::vector<std::string> {"<test attr=\"123\">value</test>"});

    auto op {bld::opBuilderSpecificHLPXMLParse(tuple)->getPtr<Term<EngineOp>>()->getFn()};
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
    auto tuple =
        std::make_tuple(std::string {"/field"},
                        std::string {"parse_xml"},
                        std::vector<std::string> {"<test attr=\"123\">value</test"});

    auto op {bld::opBuilderSpecificHLPXMLParse(tuple)->getPtr<Term<EngineOp>>()->getFn()};
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
                                 std::vector<std::string> {"$field_ref"});

    auto op {bld::opBuilderSpecificHLPXMLParse(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(
        R"({"field": "test", "field_ref": "<test attr=\"123\">value</test>"})")};

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
                                 std::vector<std::string> {"$field_ref"});

    auto op {bld::opBuilderSpecificHLPXMLParse(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_FALSE(result1);
    ASSERT_FALSE(result1.payload().get()->exists("/field_dst"));
    ASSERT_FALSE(result1.payload().get()->exists("/field_ref"));
}

// parse csv
// TODO Add test parser CSV

// parse key value
TEST(Parse_key_value, Builds)
{
    auto tuple = std::make_tuple(
        std::string {"/field"},
        std::string {"parse_key_value"},
        std::vector<std::string> {"test string map", " ", "=", "\"", "\\"});

    ASSERT_NO_THROW(bld::opBuilderSpecificHLPKeyValueParse(tuple));
}

TEST(Parse_key_value, Builds_bad_parameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_key_value"},
                                 std::vector<std::string> {"test", "TEST", "test"});

    ASSERT_THROW(bld::opBuilderSpecificHLPKeyValueParse(tuple), std::runtime_error);
}

TEST(Parse_key_value, Builds_bad_parameters2)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"parse_key_value"},
                                 std::vector<std::string> {});

    ASSERT_THROW(bld::opBuilderSpecificHLPKeyValueParse(tuple), std::runtime_error);
}

TEST(Parse_key_value, Match_value)
{
    auto tuple = std::make_tuple(
        std::string {"/field"},
        std::string {"parse_key_value"},
        std::vector<std::string> {"key1=value1 key2=\"value2\"", " ", "=", "\"", "\\"});

    auto op {
        bld::opBuilderSpecificHLPKeyValueParse(tuple)->getPtr<Term<EngineOp>>()->getFn()};
    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_TRUE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isObject("/field"));
    auto expected = R"({"key1":"value1","key2":"value2"})";
    ASSERT_STREQ(result1.payload().get()->str("/field").value().c_str(), expected);
}

TEST(Parse_key_value, Match_ref)
{
    auto tuple =
        std::make_tuple(std::string {"/field"},
                        std::string {"parse_key_value"},
                        std::vector<std::string> {"$field_ref", " ", "=", "\"", "\\"});

    auto op {
        bld::opBuilderSpecificHLPKeyValueParse(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(
        R"({"field": "test", "field_ref": "key1=value1 key2=value2"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_TRUE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isObject("/field"));
    auto expected = R"({"key1":"value1","key2":"value2"})";
    ASSERT_STREQ(result1.payload().get()->str("/field").value().c_str(), expected);
}

TEST(Parse_key_value, Match_fail)
{
    auto tuple =
        std::make_tuple(std::string {"/field"},
                        std::string {"parse_key_value"},
                        std::vector<std::string> {"$field_ref", " ", "=", "\"", "\\"});

    auto op {
        bld::opBuilderSpecificHLPKeyValueParse(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {
        std::make_shared<json::Json>(R"({"field": "test", "field_ref": "1234567890"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_FALSE(result1);
    ASSERT_TRUE(result1.payload().get()->exists("/field"));
    ASSERT_TRUE(result1.payload().get()->isString("/field"));
    ASSERT_STREQ(result1.payload().get()->getString("/field").value().c_str(), "test");
}

TEST(Parse_key_value, Ref_not_found)
{
    auto tuple =
        std::make_tuple(std::string {"/field_dst"},
                        std::string {"parse_key_value"},
                        std::vector<std::string> {"$field_ref", " ", "=", "\"", "\\"});

    auto op {
        bld::opBuilderSpecificHLPKeyValueParse(tuple)->getPtr<Term<EngineOp>>()->getFn()};

    auto event1 {std::make_shared<json::Json>(R"({"field": "test"})")};

    result::Result<Event> result1 {op(event1)};
    ASSERT_FALSE(result1);
    ASSERT_FALSE(result1.payload().get()->exists("/field_dst"));
    ASSERT_FALSE(result1.payload().get()->exists("/field_ref"));
}
