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

const std::string targetField {"/field"};
const std::string helperName {"date_from_epoch"};

TEST(opBuilderHelperDateFromEpochTime, Builds)
{
    auto tuple = std::make_tuple(std::string {targetField},
                                 std::string {helperName},
                                 std::vector<std::string> {"1685564382"},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_NO_THROW(std::apply(bld::getOpBuilderHelperDateFromEpochTime(schemf::mocks::EmptySchema::create()), tuple));
}

TEST(opBuilderHelperDateFromEpochTime, wrongParameters)
{
    // None parameter
    auto tuple = std::make_tuple(std::string {targetField},
                                 std::string {helperName},
                                 std::vector<std::string> {},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_THROW(std::apply(bld::getOpBuilderHelperDateFromEpochTime(schemf::mocks::EmptySchema::create()), tuple),
                 std::runtime_error);

    // more than 1 parameter
    tuple = std::make_tuple(std::string {targetField},
                            std::string {helperName},
                            std::vector<std::string> {"1", "2"},
                            std::make_shared<defs::mocks::FailDef>());

    ASSERT_THROW(std::apply(bld::getOpBuilderHelperDateFromEpochTime(schemf::mocks::EmptySchema::create()), tuple),
                 std::runtime_error);
}

TEST(opBuilderHelperDateFromEpochTime, nonCorrectArguments)
{
    // Big number (bigger than INT_MAX)
    auto biggerThanMax = 1 + static_cast<long int>(INT_MAX);
    auto event =
        std::make_shared<json::Json>(fmt::format(R"({{"field_ref": {}, "field": ""}})", biggerThanMax).c_str());

    // fail arguments: empty reference, non number, negative, ampty value, inexistent reference
    std::vector<std::string> arguments_array = {"$field_ref", "abcdef", "-1", "", "$someField"};
    for (const auto& argument : arguments_array)
    {
        auto tuple = std::make_tuple(std::string {targetField},
                                     std::string {helperName},
                                     std::vector<std::string> {argument},
                                     std::make_shared<defs::mocks::FailDef>());

        auto op = std::apply(bld::getOpBuilderHelperDateFromEpochTime(schemf::mocks::EmptySchema::create()), tuple)
                      ->getPtr<Term<EngineOp>>()
                      ->getFn();
        auto result = op(event);
        ASSERT_FALSE(result);
    }
}

TEST(opBuilderHelperDateFromEpochTime, executionOkWithValues)
{
    // now
    auto dateNow = date::floor<std::chrono::seconds>(std::chrono::system_clock::now());
    auto seccondsNow = std::chrono::duration_cast<std::chrono::seconds>(dateNow.time_since_epoch()).count();
    std::string epoch_now = std::to_string(seccondsNow);

    // date beginning
    date::sys_time<std::chrono::seconds> dateBegin {std::chrono::seconds {0}};

    // Now in milliseconds
    auto dateNowMilli = date::floor<std::chrono::milliseconds>(std::chrono::system_clock::now());
    auto sec = std::chrono::duration_cast<std::chrono::milliseconds>(dateNowMilli.time_since_epoch()).count();
    auto epoch_now_milli = std::to_string(static_cast<double>(sec) / 1000);

    auto event = std::make_shared<json::Json>(R"({"field": "", "reference" : 0})");

    // ok arguments and expected values:
    std::vector<std::tuple<std::string, date::sys_time<std::chrono::seconds>>> arguments_array = {
        {epoch_now, dateNow}, {"$reference", dateBegin}, {epoch_now_milli, dateNow}};

    // std::vector<std::string> arguments_array = {epoch_now, "$reference", epoch_now_milli};
    for (const auto& argument : arguments_array)
    {
        auto tuple = std::make_tuple(std::string {targetField},
                                     std::string {helperName},
                                     std::vector<std::string> {std::get<0>(argument)},
                                     std::make_shared<defs::mocks::FailDef>());

        auto op = std::apply(bld::getOpBuilderHelperDateFromEpochTime(schemf::mocks::EmptySchema::create()), tuple)
                      ->getPtr<Term<EngineOp>>()
                      ->getFn();
        auto result = op(event);

        ASSERT_TRUE(result);
        ASSERT_TRUE(result.payload()->getString(targetField));

        auto resultString = result.payload()->getString(targetField).value();
        auto nowStrResult = date::format("%Y-%m-%dT%H:%M:%SZ", std::get<1>(argument));
        ASSERT_STREQ(resultString.c_str(), nowStrResult.c_str());
    }
}
