#include <gtest/gtest.h>
#include <rxcpp/rx.hpp>

#include "asset_builder.hpp"
#include "registry.hpp"
#include "test_utils.hpp"

using condition_builder_t =
    AssetBuilder<observable<event>(observable<event>, value_t)>;

TEST(ConditionBuilderTest, Initializes) {
  ASSERT_NO_THROW(
      Registry::instance().builder<condition_builder_t>("condition"));
}

TEST(ConditionBuilderTest, BuildsConditionValue) {
  // Fake entry poing
  auto entry_point = rxcpp::observable<>::create<event>(handler);

  // Fake input json
  auto fake_jstring = R"(
      {
          "check": {
              "field": 1
          }
      }
  )";
  json::Document fake_j{fake_jstring};

  // Retreive builder
  auto _builder =
      Registry::instance().builder<condition_builder_t>("condition");

  // Build
  ASSERT_NO_THROW(auto _observable =
                      _builder(entry_point, fake_j.get(".check")));
}

TEST(ConditionBuilderTest, BuildsConditionExists) {
  // Fake entry poing
  auto entry_point = rxcpp::observable<>::create<event>(handler);

  // Fake input json
  auto fake_jstring = R"(
      {
          "check": {
              "field": "+exists"
          }
      }
  )";
  json::Document fake_j{fake_jstring};

  // Retreive builder
  auto _builder =
      Registry::instance().builder<condition_builder_t>("condition");

  // Build
  ASSERT_NO_THROW(auto _observable =
                      _builder(entry_point, fake_j.get(".check")));
}

TEST(ConditionBuilderTest, BuildsConditionNotExists) {
  // Fake entry poing
  auto entry_point = rxcpp::observable<>::create<event>(handler);

  // Fake input json
  auto fake_jstring = R"(
      {
          "check": {
              "field": "+not_exists"
          }
      }
  )";
  json::Document fake_j{fake_jstring};

  // Retreive builder
  auto _builder =
      Registry::instance().builder<condition_builder_t>("condition");

  // Build
  ASSERT_NO_THROW(auto _observable =
                      _builder(entry_point, fake_j.get(".check")));
}
