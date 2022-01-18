#include <gtest/gtest.h>
#include <string>

#include "asset_builder.hpp"

using namespace std;
using namespace builder::internals;

int fn(string strNumber, int number) { return number + stoi(strNumber); }
using AssetBuilderType = AssetBuilder<int(string, int)>;

TEST(ComponentBuilder, Constructs) {
  ASSERT_NO_THROW(AssetBuilderType test_builder("test_builder", fn));
}

TEST(ComponentBuilder, Builds) {
  AssetBuilderType test_builder("test_builder", fn);
  ASSERT_EQ(test_builder("1", 1), 2);
}
