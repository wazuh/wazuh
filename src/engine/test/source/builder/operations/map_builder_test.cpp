#include <gtest/gtest.h>
#include <rxcpp/rx.hpp>

#include "asset_builder.hpp"
#include "registry.hpp"
#include "test_utils.hpp"

using map_builder_t =
    AssetBuilder<observable<event>(observable<event>, value_t)>;

TEST(MapBuilderTest, Initializes) {
  ASSERT_NO_THROW(Registry::instance().builder<map_builder_t>("map"));
}

TEST(MapBuilderTest, BuildsMapValue) {
  // Fake entry poing
  auto entry_point = rxcpp::observable<>::create<event>(handler);

  // Fake input json
  auto fake_jstring = R"(
      {
          "check": {
              "mapped_field": 1
          }
      }
  )";
  json::Document fake_j{fake_jstring};

  // Retreive builder
  auto _builder = Registry::instance().builder<map_builder_t>("map");

  // Build
  ASSERT_NO_THROW(auto _observable =
                      _builder(entry_point, fake_j.get(".check")));
}
