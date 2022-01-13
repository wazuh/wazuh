#include <gtest/gtest.h>
#include <string>

#include "builder.hpp"

using namespace std;
using namespace builder::internals;

int fn(string strNumber, int number) { return number + stoi(strNumber); }
typedef Builder<int(string, int)> BuilderType;

TEST(Builder, Constructs) {
  ASSERT_NO_THROW(BuilderType test_builder("test_builder", fn));
}

TEST(Builder, Builds) {
  BuilderType test_builder("test_builder", fn);
  ASSERT_EQ(test_builder("1", 1), 2);
}
