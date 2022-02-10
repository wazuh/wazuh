#include <gtest/gtest.h>

#include "register.hpp"
#include "registry.hpp"

using namespace builder::internals;

TEST(Register, AllBuildersRegistered)
{
    ASSERT_NO_THROW(registerBuilders());

    // Check all builders have been registered
    ASSERT_NO_THROW(Registry::getBuilder("condition.value"));
    ASSERT_NO_THROW(Registry::getBuilder("condition"));
}
