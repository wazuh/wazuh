#include <any>
#include <gtest/gtest.h>
#include <vector>
#include <ctime>

#include <baseTypes.hpp>

#include "opBuilderHelperMap.hpp"

using namespace base;
namespace bld = builder::internals::builders;

TEST(opBuilderHelperTimeEpoch, Builds)
{
    auto tuple = std::make_tuple(
        std::string {"/field"}, std::string {" system_epoch"}, std::vector<std::string> {});

    ASSERT_NO_THROW(bld::opBuilderHelperEpochTimeFromSystem(tuple));
}

TEST(opBuilderHelperTimeEpoch, Builds_bad_parameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {" system_epoch"},
                                 std::vector<std::string> {"test"});

    ASSERT_THROW(bld::opBuilderHelperEpochTimeFromSystem(tuple), std::runtime_error);
}

TEST(opBuilderHelperTimeEpoch, Exec_string_UP_field_not_exist)
{
    auto tuple = std::make_tuple(
        std::string {"/field"}, std::string {" system_epoch"}, std::vector<std::string> {});

    auto event1 = std::make_shared<json::Json>(R"({"fieldcheck": 10})");

    auto op = bld::opBuilderHelperEpochTimeFromSystem(tuple)->getPtr<Term<EngineOp>>()->getFn();

    auto result = op(event1);
    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->getInt("/field"));
    auto nowSec = result.payload()->getInt("/field").value_or(-2); // std::chrono::seconds
    auto time2 = std::time(nullptr);
    ASSERT_NEAR(nowSec, time2, 1);

}
