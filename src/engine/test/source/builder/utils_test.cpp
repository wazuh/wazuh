#include <algorithm>
#include <gtest/gtest.h>

#include "utils.hpp"

using namespace std;
using namespace builder::internals;

TEST(BuilderUtils, JsonPath) {
  string s = "this.is.some.string";
  vector<string> expected{"this", "is", "some", "string"};
  utils::JsonPath jP(s);
  auto i = 0;
  for_each(jP.begin(), jP.end(), [&i, &expected](auto field) {
    ASSERT_EQ(field, expected[i]);
    i++;
  });
}
