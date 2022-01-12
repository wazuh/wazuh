#include <gtest/gtest.h>
#include <string>

#include "registry.hpp"

using namespace std;
using namespace builder::internals;

string g_builderId = "test builder";
int g_builder = 0;

TEST(Registry, RegisterNewBuilder) {
  ASSERT_NO_THROW(Registry::instance().registerBuilder<int>(g_builderId, g_builder));
}

TEST(Registry, RegisterExistingBuilder) {
  ASSERT_THROW(Registry::instance().registerBuilder<int>(g_builderId, g_builder), invalid_argument);
}

TEST(Registry, getExistingBuilder) {
  ASSERT_NO_THROW(Registry::instance().builder<int>(g_builderId));
}

TEST(Registry, getNonExistingBuilder) {
  ASSERT_THROW(Registry::instance().builder<int>("none"), out_of_range);
}
