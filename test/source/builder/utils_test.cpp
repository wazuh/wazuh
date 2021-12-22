#include <gtest/gtest.h>
#include <algorithm>

#include "builder.hpp"
#include "utils.hpp"

#define GTEST_COUT std::cerr << "[          ] [ INFO ] "


using namespace std;

TEST(BuilderUtils, JsonPath)
{
    string s = "this.is.some.string";
    vector<string> expected{"this", "is", "some", "string"};
    builder::utils::JsonPath jp(s);
    auto i = 0;
    for_each(jp.begin(), jp.end(), [&i, &expected](auto field)
    {
        ASSERT_EQ(field, expected[i]);
        i++;
    });

}
