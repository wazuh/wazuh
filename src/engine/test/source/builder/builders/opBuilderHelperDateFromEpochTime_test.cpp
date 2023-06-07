#include <any>
#include <chrono>
#include <gtest/gtest.h>
#include <vector>

#include <baseTypes.hpp>
#include <schemf/mocks/emptySchema.hpp>

#include "opBuilderHelperMap.hpp"
#include <date/date.h>
#include <date/tz.h>
#include <defs/mocks/failDef.hpp>

using namespace base;
namespace bld = builder::internals::builders;

TEST(opBuilderHelperDateFromEpochTime, Builds)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"date_from_epoch"},
                                 std::vector<std::string> {"1685564382"},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_NO_THROW(std::apply(bld::getOpBuilderHelperDateFromEpochTime(schemf::mocks::EmptySchema::create()), tuple));
}

TEST(opBuilderHelperDateFromEpochTime, wrongParameters)
{
    // None parameter
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"date_from_epoch"},
                                 std::vector<std::string> {},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_THROW(std::apply(bld::getOpBuilderHelperDateFromEpochTime(schemf::mocks::EmptySchema::create()), tuple),
                 std::runtime_error);

    // more than 1 parameter
    tuple = std::make_tuple(std::string {"/field"},
                            std::string {"date_from_epoch"},
                            std::vector<std::string> {"1", "2"},
                            std::make_shared<defs::mocks::FailDef>());

    ASSERT_THROW(std::apply(bld::getOpBuilderHelperDateFromEpochTime(schemf::mocks::EmptySchema::create()), tuple),
                 std::runtime_error);

    // reference doesn't exist
    tuple = std::make_tuple(std::string {"/field"},
                            std::string {"date_from_epoch"},
                            std::vector<std::string> {"$someField"},
                            std::make_shared<defs::mocks::FailDef>());

    auto event = std::make_shared<json::Json>(R"({"otherField": 10})");
    auto op = std::apply(bld::getOpBuilderHelperDateFromEpochTime(schemf::mocks::EmptySchema::create()), tuple)
                  ->getPtr<Term<EngineOp>>()
                  ->getFn();
    auto result = op(event);
    ASSERT_FALSE(result);

    // empty parameter
    tuple = std::make_tuple(std::string {"/field"},
                            std::string {"date_from_epoch"},
                            std::vector<std::string> {""},
                            std::make_shared<defs::mocks::FailDef>());

    event = std::make_shared<json::Json>(R"({"field": ""})");
    op = std::apply(bld::getOpBuilderHelperDateFromEpochTime(schemf::mocks::EmptySchema::create()), tuple)
             ->getPtr<Term<EngineOp>>()
             ->getFn();
    result = op(event);
    ASSERT_FALSE(result);
}

TEST(opBuilderHelperDateFromEpochTime, inputNumberOutsideOfLimits)
{
    // Big number (bigger than INT_MAX)
    auto biggerThanMax = 1 + static_cast<long int>(INT_MAX);
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"date_from_epoch"},
                                 std::vector<std::string> {"$field_ref"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto event = std::make_shared<json::Json>(fmt::format(R"({{"field_ref": {}}})",biggerThanMax).c_str());
    auto op = std::apply(bld::getOpBuilderHelperDateFromEpochTime(schemf::mocks::EmptySchema::create()), tuple)
                  ->getPtr<Term<EngineOp>>()
                  ->getFn();
    auto result = op(event);
    ASSERT_FALSE(result);

    // parameter not number
    tuple = std::make_tuple(std::string {"/field"},
                            std::string {"date_from_epoch"},
                            std::vector<std::string> {"abcdef"},
                            std::make_shared<defs::mocks::FailDef>());

    event = std::make_shared<json::Json>(R"({"field": ""})");
    op = std::apply(bld::getOpBuilderHelperDateFromEpochTime(schemf::mocks::EmptySchema::create()), tuple)
             ->getPtr<Term<EngineOp>>()
             ->getFn();
    result = op(event);
    ASSERT_FALSE(result);

    // negative
    tuple = std::make_tuple(std::string {"/field"},
                            std::string {"date_from_epoch"},
                            std::vector<std::string> {"-1"},
                            std::make_shared<defs::mocks::FailDef>());

    event = std::make_shared<json::Json>(R"({"field": ""})");
    op = std::apply(bld::getOpBuilderHelperDateFromEpochTime(schemf::mocks::EmptySchema::create()), tuple)
             ->getPtr<Term<EngineOp>>()
             ->getFn();
    result = op(event);
    ASSERT_FALSE(result);
}

TEST(opBuilderHelperDateFromEpochTime, executionOkWithValues)
{
    // now
    auto dateNow = date::floor<std::chrono::seconds>(std::chrono::system_clock::now());
    auto seccondsNow = std::chrono::duration_cast<std::chrono::seconds>(dateNow.time_since_epoch()).count();
    std::string epoch_now = std::to_string(seccondsNow);

    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"date_from_epoch"},
                                 std::vector<std::string> {epoch_now},
                                 std::make_shared<defs::mocks::FailDef>());

    auto event = std::make_shared<json::Json>(R"({"field": "", "reference" : 0})");
    auto op = std::apply(bld::getOpBuilderHelperDateFromEpochTime(schemf::mocks::EmptySchema::create()), tuple)
                  ->getPtr<Term<EngineOp>>()
                  ->getFn();
    auto result = op(event);

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->getString("/field"));
    auto nowSec = result.payload()->getString("/field").value();
    auto nowStrResult = date::format("%Y-%m-%dT%H:%M:%SZ", dateNow);
    ASSERT_STREQ(nowStrResult.c_str(), nowSec.c_str());

    // epoch zero with reference
    auto tuple2 = std::make_tuple(std::string {"/field"},
                                  std::string {"date_from_epoch"},
                                  std::vector<std::string> {"$reference"},
                                  std::make_shared<defs::mocks::FailDef>());

    op = std::apply(bld::getOpBuilderHelperDateFromEpochTime(schemf::mocks::EmptySchema::create()), tuple2)
             ->getPtr<Term<EngineOp>>()
             ->getFn();
    result = op(event);

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->getString("/field"));
    nowSec = result.payload()->getString("/field").value();
    date::sys_time<std::chrono::seconds> tp {std::chrono::seconds {0}};
    nowStrResult = date::format("%Y-%m-%dT%H:%M:%SZ", tp);
    ASSERT_STREQ(nowStrResult.c_str(), nowSec.c_str());
}

TEST(opBuilderHelperDateFromEpochTime, SuccessTruncatingFloatingPoint)
{
    // Now in milliseconds
    auto dateNowMilli = date::floor<std::chrono::milliseconds>(std::chrono::system_clock::now());
    auto sec = std::chrono::duration_cast<std::chrono::milliseconds>(dateNowMilli.time_since_epoch()).count();
    double secWithComma = static_cast<double>(sec) / 1000;
    std::string epoch_now = std::to_string(secWithComma);
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"date_from_epoch"},
                                 std::vector<std::string> {epoch_now},
                                 std::make_shared<defs::mocks::FailDef>());

    auto event = std::make_shared<json::Json>(R"({})");
    auto op = std::apply(bld::getOpBuilderHelperDateFromEpochTime(schemf::mocks::EmptySchema::create()), tuple)
                  ->getPtr<Term<EngineOp>>()
                  ->getFn();
    auto result = op(event);

    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->getString("/field"));

    // Result in string will truncate to only seconds
    auto nowSec = result.payload()->getString("/field").value();
    date::sys_time<std::chrono::seconds> tp {std::chrono::seconds {std::stoi(epoch_now)}};
    auto now_str_result = date::format("%Y-%m-%dT%H:%M:%SZ", tp);
    ASSERT_STREQ(now_str_result.c_str(), nowSec.c_str());
}
