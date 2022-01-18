#include <gtest/gtest.h>
#include <string>

#include "asset_builder.hpp"
#include "registry.hpp"

using namespace std;
using namespace builder::internals;

int fn(string strNumber, int number) { return number + stoi(strNumber); }
using AssetBuilderType = AssetBuilder<int(string, int)>;

TEST(ComponentBuilder, Constructs) {
  ASSERT_NO_THROW(AssetBuilderType test_builder("test_builder", fn));
}

TEST(ComponentBuilder, RegisteredOnConstruction) {
  ASSERT_NO_THROW(Registry::instance().builder<AssetBuilderType>("test_builder"));
}

TEST(ComponentBuilder, ErrorOnDuplicatedConstruction) {
  ASSERT_THROW(AssetBuilderType test_builder("test_builder", fn), invalid_argument);
}

TEST(ComponentBuilder, Builds) {
  ASSERT_EQ(Registry::instance().builder<AssetBuilderType>("test_builder")("1", 1), 2);
}
