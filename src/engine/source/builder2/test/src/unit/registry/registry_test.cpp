#include <gtest/gtest.h>

#include "mockRegistry.hpp" // Force include to ensure it compiles
#include "registry/registry.hpp"

using namespace builder::registry;

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

TEST(RegistryTest, Mock)
{
    mock::MockRegistry<int> registry;
    EXPECT_CALL(registry, add("test", 1)).WillOnce(testing::Return(base::Error {}));
    auto err = registry.add("test", 1);
    EXPECT_TRUE(err.has_value());

    EXPECT_CALL(registry, get("test")).WillOnce(testing::Return(mock::getError<int>()));
    auto resp = registry.get("test");
    EXPECT_TRUE(base::isError(resp));
}
