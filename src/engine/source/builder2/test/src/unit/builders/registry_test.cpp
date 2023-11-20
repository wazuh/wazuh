#include <gtest/gtest.h>

#include "mockRegistry.hpp" // Force include to ensure it compiles
#include "builders/registry.hpp"

using namespace builder::builders;
using namespace builder::builders::mocks;

TEST(RegistryTest, Add)
{
    Registry<int> registry;
    EXPECT_FALSE(registry.add("test", 1).has_value());
}

TEST(RegistryTest, AddFailAlreadyRegistered)
{
    Registry<int> registry;
    EXPECT_FALSE(registry.add("test", 1).has_value());
    EXPECT_TRUE(registry.add("test", 1).has_value());
}

TEST(RegistryTest, Get)
{
    Registry<int> registry;
    EXPECT_FALSE(registry.add("test", 1).has_value());
    auto resp = registry.get("test");
    EXPECT_FALSE(base::isError(resp));
    EXPECT_EQ(base::getResponse<int>(resp), 1);
}

TEST(RegistryTest, GetFailNotRegistered)
{
    Registry<int> registry;
    auto resp = registry.get("test");
    EXPECT_TRUE(base::isError(resp));
}

// Ensure that the mock registry compiles, needs to be instantiated because it's a template
TEST(RegistryTest, Mock)
{
    MockRegistry<int> registry;
    EXPECT_CALL(registry, add("test", 1)).WillOnce(testing::Return(base::Error {}));
    auto err = registry.add("test", 1);
    EXPECT_TRUE(err.has_value());

    EXPECT_CALL(registry, get("test")).WillOnce(testing::Return(getError<int>()));
    auto resp = registry.get("test");
    EXPECT_TRUE(base::isError(resp));
}
