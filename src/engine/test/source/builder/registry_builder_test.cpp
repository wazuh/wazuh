#include <gtest/gtest.h>
#include <string>

#include "builder.hpp"
#include "registry.hpp"

using namespace std;
using namespace builder::internals;

string name_1 = "builder 1";
string name_2 = "builder 2";
string name_3 = "builder 3";

auto fn_1 = [](int i) { return i + 1; };
auto fn_2 = [](string s) {
  s.push_back('_');
  s.push_back('1');
  return s;
};
auto fn_3 = [](Builder<int(int)> builder_1, Builder<string(string)> builder_2) {
  return [=](int i, string s) {
    auto res_1 = builder_1(i);
    auto res_2 = builder_2(s);
    return tuple<int, string>{res_1, res_2};
  };
};

Registry &g_reg = Registry::instance();
typedef Builder<int(int)> builder_1t;
typedef Builder<string(string)> builder_2t;
typedef Builder<function<tuple<int, string>(int, string)>(builder_1t,
                                                          builder_2t)>
    builder_3t;

TEST(RegistryBuilder, BuildAndRegister) {
  builder_1t builder_1{name_1, fn_1};
  ASSERT_NO_THROW(g_reg.registerBuilder<builder_1t>(name_1, builder_1));
  builder_2t builder_2{name_2, fn_2};
  ASSERT_NO_THROW(g_reg.registerBuilder<builder_2t>(name_2, builder_2));
  builder_3t builder_3{name_3, fn_3};
  ASSERT_NO_THROW(g_reg.registerBuilder<builder_3t>(name_3, builder_3));
}

TEST(RegistryBuilder, ReRegisterError) {
  builder_1t builder_1{name_1, fn_1};
  ASSERT_THROW(g_reg.registerBuilder<builder_1t>(name_1, builder_1),
               invalid_argument);
  builder_2t builder_2{name_2, fn_2};
  ASSERT_THROW(g_reg.registerBuilder<builder_2t>(name_2, builder_2),
               invalid_argument);
  builder_3t builder_3{name_3, fn_3};
  ASSERT_THROW(g_reg.registerBuilder<builder_3t>(name_3, builder_3),
               invalid_argument);
}

TEST(RegistryBuilder, GetBuilders) {
  ASSERT_NO_THROW(auto builder_1 = g_reg.builder<builder_1t>(name_1));
  ASSERT_NO_THROW(auto builder_2 = g_reg.builder<builder_2t>(name_2));
  ASSERT_NO_THROW(auto builder_3 = g_reg.builder<builder_3t>(name_3));
}

TEST(RegistryBuilder, GetBuildersAndBuild) {
  auto builder_1 = g_reg.builder<builder_1t>(name_1);
  ASSERT_EQ(builder_1(1), 2);
  auto builder_2 = g_reg.builder<builder_2t>(name_2);
  ASSERT_EQ(builder_2("1"), "1_1");
  auto builder_3 = g_reg.builder<builder_3t>(name_3);
  auto res = tuple<int, string>{2, "1_1"};
  ASSERT_EQ(builder_3(builder_1, builder_2)(1, "1"), res);
}
