#include <gtest/gtest.h>

#include <kvdb/mockKvdbManager.hpp>
#include <logpar/logpar.hpp>
#include <schemf/mockSchema.hpp>

#include "builders/ibuildCtx.hpp"
#include "mockRegistry.hpp" // Force include to ensure it compiles
#include "register.hpp"
#include "registry.hpp"

using namespace builder;
using namespace builder::mocks;

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

TEST(RegistryTest, MetaRegistry)
{
    auto metaRegistry = MetaRegistry<int, std::string>::create<Registry>();

    metaRegistry->add<int>("test", 1);
    metaRegistry->add<std::string>("test", "test");

    auto l = [](std::shared_ptr<MetaRegistry<int, std::string>> metaRegistry)
    {
        auto intBuilder = metaRegistry->get<int>("test");
        auto strBuilder = metaRegistry->get<std::string>("test");

        ASSERT_EQ(base::getResponse<int>(intBuilder), 1);
        ASSERT_EQ(base::getResponse<std::string>(strBuilder), "test");

        auto missIntBuilder = metaRegistry->get<int>("miss");
        auto missStrBuilder = metaRegistry->get<std::string>("miss");

        ASSERT_TRUE(base::isError(missIntBuilder));
        ASSERT_TRUE(base::isError(missStrBuilder));

        // Compile failure
        // metaRegistry->get<float>("test");
    };

    l(metaRegistry);
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

TEST(RegistryTest, MetaRegistryMock)
{
    auto mockMetaRegistry = MockMetaRegistry<int, std::string>::createMock();
    EXPECT_CALL(mockMetaRegistry->getRegistry<int>(), get("test")).WillOnce(testing::Return(1));
    EXPECT_CALL(mockMetaRegistry->getRegistry<std::string>(), get("test")).WillOnce(testing::Return("test"));
    EXPECT_CALL(mockMetaRegistry->getRegistry<int>(), get("miss")).WillOnce(testing::Return(getError<int>()));
    EXPECT_CALL(mockMetaRegistry->getRegistry<std::string>(), get("miss"))
        .WillOnce(testing::Return(getError<std::string>()));

    auto l = [](std::shared_ptr<MetaRegistry<int, std::string>> metaRegistry)
    {
        auto intBuilder = metaRegistry->get<int>("test");
        auto strBuilder = metaRegistry->get<std::string>("test");

        ASSERT_EQ(base::getResponse<int>(intBuilder), 1);
        ASSERT_EQ(base::getResponse<std::string>(strBuilder), "test");

        auto missIntBuilder = metaRegistry->get<int>("miss");
        auto missStrBuilder = metaRegistry->get<std::string>("miss");

        ASSERT_TRUE(base::isError(missIntBuilder));
        ASSERT_TRUE(base::isError(missStrBuilder));

        // Compile failure
        // metaRegistry->get<float>("test");
    };

    l(mockMetaRegistry);
}

TEST(RegistryTest, RegisterBuilders)
{
    // TODO update to use logpar mock when implemented
    auto metaRegistry = builders::RegistryType::create<Registry>();
    BuilderDeps deps {};
    json::Json fakeLogparDefs;
    fakeLogparDefs.setString("name", "/name");
    fakeLogparDefs.setObject("/fields");
    deps.logpar = std::make_shared<hlp::logpar::Logpar>(fakeLogparDefs, std::make_shared<schemf::mocks::MockSchema>());
    deps.kvdbManager = std::make_shared<kvdb::mocks::MockKVDBManager>();
    deps.kvdbScopeName = "test";
    deps.logparDebugLvl = 0;

    ASSERT_NO_THROW(builder::detail::registerOpBuilders<builders::RegistryType>(metaRegistry, deps));
    ASSERT_NO_THROW(builder::detail::registerStageBuilders<builders::RegistryType>(metaRegistry, deps));
}
