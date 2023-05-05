#include <any>
#include <ctime>
#include <gtest/gtest.h>
#include <vector>

#include <baseTypes.hpp>
#include <defs/mocks/failDef.hpp>

#include "opBuilderHelperMap.hpp"

using namespace base;
namespace bld = builder::internals::builders;

TEST(opBuilderHelperTimeEpoch, Builds)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {" system_epoch"},
                                 std::vector<std::string> {},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_NO_THROW(std::apply(bld::opBuilderHelperEpochTimeFromSystem, tuple));
}

TEST(opBuilderHelperTimeEpoch, Builds_bad_parameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {" system_epoch"},
                                 std::vector<std::string> {"test"},
                                 std::make_shared<defs::mocks::FailDef>());

    ASSERT_THROW(std::apply(bld::opBuilderHelperEpochTimeFromSystem, tuple), std::runtime_error);
}

TEST(opBuilderHelperTimeEpoch, Exec_string_UP_field_not_exist)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {" system_epoch"},
                                 std::vector<std::string> {},
                                 std::make_shared<defs::mocks::FailDef>());

    auto event1 = std::make_shared<json::Json>(R"({"fieldcheck": 10})");

    auto op = std::apply(bld::opBuilderHelperEpochTimeFromSystem, tuple)->getPtr<Term<EngineOp>>()->getFn();

    auto result = op(event1);
    ASSERT_TRUE(result);
    ASSERT_TRUE(result.payload()->getInt("/field"));
    auto nowSec = result.payload()->getInt("/field").value_or(-2); // std::chrono::seconds
    auto time2 = std::time(nullptr);
    ASSERT_NEAR(nowSec, time2, 1);
}
