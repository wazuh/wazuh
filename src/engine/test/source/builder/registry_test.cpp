#include <gtest/gtest.h>

#include "registry.hpp"

using namespace builder::internals;

Expression builderDummy(std::any)
{
    Expression expression;
    return expression;
}

class RegistryTest : public ::testing::Test
{
protected:
    void TearDown() override
    {
        Registry::clear();
    }
};

TEST_F(RegistryTest, RegisterBuilder)
{
    ASSERT_NO_THROW(Registry::registerBuilder(builderDummy, "test"));
}

TEST_F(RegistryTest, RegisterBuilderMultipleNames)
{
    ASSERT_NO_THROW(Registry::registerBuilder(builderDummy, "test", "test2", "test3"));
}

TEST_F(RegistryTest, RegisterBuilderDuplicateName)
{
    ASSERT_NO_THROW(Registry::registerBuilder(builderDummy, "test"));
    ASSERT_THROW(Registry::registerBuilder(builderDummy, "test"), std::logic_error);
}

TEST_F(RegistryTest, GetBuilder)
{
    ASSERT_NO_THROW(Registry::registerBuilder(builderDummy, "test"));
    ASSERT_NO_THROW(Registry::getBuilder("test"));
}

TEST_F(RegistryTest, GetBuilderMultipleNames)
{
    ASSERT_NO_THROW(Registry::registerBuilder(builderDummy, "test", "test2", "test3"));
    ASSERT_NO_THROW(Registry::getBuilder("test"));
    ASSERT_NO_THROW(Registry::getBuilder("test2"));
    ASSERT_NO_THROW(Registry::getBuilder("test3"));
}

TEST_F(RegistryTest, GetBuilderNotRegistered)
{
    ASSERT_THROW(Registry::getBuilder("test"), std::runtime_error);
}

TEST_F(RegistryTest, Clear)
{
    ASSERT_NO_THROW(Registry::registerBuilder(builderDummy, "test"));
    ASSERT_NO_THROW(Registry::clear());
    ASSERT_THROW(Registry::getBuilder("test"), std::runtime_error);
}

TEST_F(RegistryTest, ClearTwice)
{
    ASSERT_NO_THROW(Registry::clear());
    ASSERT_NO_THROW(Registry::clear());
}

TEST_F(RegistryTest, UseCase)
{
    ASSERT_NO_THROW(Registry::registerBuilder(builderDummy, "test"));
    Builder builder;
    ASSERT_NO_THROW(builder = Registry::getBuilder("test"));
    ASSERT_NO_THROW(builder(std::any {}));

    ASSERT_THROW(Registry::getBuilder("test2"), std::runtime_error);

    ASSERT_NO_THROW(Registry::registerBuilder(builderDummy, "test2"));
    ASSERT_NO_THROW(builder = Registry::getBuilder("test2"));
    ASSERT_NO_THROW(builder(std::any {}));

    ASSERT_THROW(Registry::registerBuilder(builderDummy, "test"), std::logic_error);

    ASSERT_NO_THROW(Registry::clear());
    ASSERT_THROW(Registry::getBuilder("test"), std::runtime_error);
    ASSERT_THROW(Registry::getBuilder("test2"), std::runtime_error);
}
