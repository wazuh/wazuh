#include <gtest/gtest.h>

#include "builder.hpp"
#include "registry.hpp"

#define GTEST_COUT std::cout << "[          ] [ INFO ] "


using namespace std;

TEST(ConditionValueTest, Initializes)
{
    // Get registry instance as all builders are only accesible by it
    builder::Registry& registry = builder::Registry::instance();

    // Retreive builder
    ASSERT_NO_THROW(auto builder = registry.get_builder("condition"));
}
