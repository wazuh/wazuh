#include <gtest/gtest.h>

#include "baseTypes.hpp"
#include "registry.hpp"

using namespace builder::internals;
using namespace base;

Expression builderDummy(std::any)
{
    Expression expression;
    return expression;
}

TEST(RegistryTest, RegisterBuilder)
{
    Registry registry;
    ASSERT_NO_THROW(registry.registerBuilder(builderDummy, "test"));
}

TEST(RegistryTest, RegisterBuilderMultipleNames)
{
    Registry registry;
    ASSERT_NO_THROW(registry.registerBuilder(builderDummy, "test", "test2", "test3"));
}

TEST(RegistryTest, RegisterBuilderDuplicateName)
{
    Registry registry;
    ASSERT_NO_THROW(registry.registerBuilder(builderDummy, "test"));
    ASSERT_THROW(registry.registerBuilder(builderDummy, "test"), std::logic_error);
}

TEST(RegistryTest, GetBuilder)
{
    Registry registry;
    ASSERT_NO_THROW(registry.registerBuilder(builderDummy, "test"));
    ASSERT_NO_THROW(registry.getBuilder("test"));
}

TEST(RegistryTest, GetBuilderMultipleNames)
{
    Registry registry;
    ASSERT_NO_THROW(registry.registerBuilder(builderDummy, "test", "test2", "test3"));
    ASSERT_NO_THROW(registry.getBuilder("test"));
    ASSERT_NO_THROW(registry.getBuilder("test2"));
    ASSERT_NO_THROW(registry.getBuilder("test3"));
}

TEST(RegistryTest, GetBuilderNotRegistered)
{
    Registry registry;
    ASSERT_THROW(registry.getBuilder("test"), std::runtime_error);
}

TEST(RegistryTest, Clear)
{
    Registry registry;
    ASSERT_NO_THROW(registry.registerBuilder(builderDummy, "test"));
    ASSERT_NO_THROW(registry.clear());
    ASSERT_THROW(registry.getBuilder("test"), std::runtime_error);
}

TEST(RegistryTest, ClearTwice)
{
    Registry registry;
    ASSERT_NO_THROW(registry.clear());
    ASSERT_NO_THROW(registry.clear());
}

TEST(RegistryTest, UseCase)
{
    Registry registry;
    ASSERT_NO_THROW(registry.registerBuilder(builderDummy, "test"));
    Builder builder;
    ASSERT_NO_THROW(builder = registry.getBuilder("test"));
    ASSERT_NO_THROW(builder(std::any {}));

    ASSERT_THROW(registry.getBuilder("test2"), std::runtime_error);

    ASSERT_NO_THROW(registry.registerBuilder(builderDummy, "test2"));
    ASSERT_NO_THROW(builder = registry.getBuilder("test2"));
    ASSERT_NO_THROW(builder(std::any {}));

    ASSERT_THROW(registry.registerBuilder(builderDummy, "test"), std::logic_error);

    ASSERT_NO_THROW(registry.clear());
    ASSERT_THROW(registry.getBuilder("test"), std::runtime_error);
    ASSERT_THROW(registry.getBuilder("test2"), std::runtime_error);
}
