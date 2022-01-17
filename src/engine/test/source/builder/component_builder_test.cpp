#include <gtest/gtest.h>
#include <string>

#include "component_builder.hpp"

using namespace std;
using namespace builder::internals;

int fn(string strNumber, int number) { return number + stoi(strNumber); }
typedef ComponentBuilder<int(string, int)> ComponentBuilderType;

TEST(ComponentBuilder, Constructs) {
  ASSERT_NO_THROW(ComponentBuilderType test_builder("test_builder", fn));
}

TEST(ComponentBuilder, Builds) {
  ComponentBuilderType test_builder("test_builder", fn);
  ASSERT_EQ(test_builder("1", 1), 2);
}
