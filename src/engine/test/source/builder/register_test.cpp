#include <gtest/gtest.h>

#include "builder/register.hpp"
#include "builder/registry.hpp"

using namespace builder::internals;

class RegisterTest : public ::testing::Test
{
protected:
    void TearDown() override
    {
        Registry::clear();
    }
};

TEST(RegisterTest, AllBuildersRegistered)
{
    ASSERT_NO_THROW(registerBuilders());

    // Check all builders have been registered
    ASSERT_NO_THROW(Registry::getBuilder("operation.map"));
    ASSERT_NO_THROW(Registry::getBuilder("operation.condition"));
    ASSERT_NO_THROW(Registry::getBuilder("stage.check"));
    ASSERT_NO_THROW(Registry::getBuilder("stage.map"));
    ASSERT_NO_THROW(Registry::getBuilder("stage.normalize"));
}
