#include <gtest/gtest.h>

#include <bk/mockController.hpp>
#include <builder/mockBuilder.hpp>
#include <builder/mockPolicy.hpp>

#include "router.hpp"

const std::string ENVIRONMENT_NAME = "Production";
const std::string POLICY_NAME = "policy/name/0";
const std::string FILTER_NAME = "filter/name/0";
const uint32_t PRIORITY = 99;

class RouterTest : public ::testing::Test
{
protected:
    std::shared_ptr<builder::mocks::MockBuilder> m_mockBuilder;
    std::shared_ptr<bk::mocks::MockMakerController> m_mockControllerMaker;
    std::shared_ptr<bk::mocks::MockController> m_mockController;
    std::shared_ptr<builder::mocks::MockPolicy> m_mockPolicy;
    std::shared_ptr<router::Router> m_router;

public:
    void SetUp() override
    {
        m_mockBuilder = std::make_shared<builder::mocks::MockBuilder>();
        m_mockControllerMaker = std::make_shared<bk::mocks::MockMakerController>();
        m_mockController = std::make_shared<bk::mocks::MockController>();
        m_mockPolicy = std::make_shared<builder::mocks::MockPolicy>();
        auto environmentBuilder = std::make_shared<router::EnvironmentBuilder>(m_mockBuilder, m_mockControllerMaker);
        m_router = std::make_shared<router::Router>(environmentBuilder);
    }

    void TearDown() override { m_router.reset(); }

    void makeControllerNamePolicyFailture(router::prod::EntryPost entryPost)
    {
        auto error = m_router->addEntry(entryPost);
        EXPECT_TRUE(error.has_value());
    }

    void makeControllerBuildPolicyFailture(router::prod::EntryPost entryPost)
    {
        EXPECT_CALL(*m_mockBuilder, buildPolicy(testing::_)).WillOnce(::testing::Throw(std::runtime_error("error")));
        auto error = m_router->addEntry(entryPost);
        EXPECT_TRUE(error.has_value());
    }

    void makeControllerBuildPolicySuccess()
    {
        EXPECT_CALL(*m_mockBuilder, buildPolicy(testing::_)).WillOnce(::testing::Return(m_mockPolicy));
    }

    void makeControllerPolicyAssetsFailture(router::prod::EntryPost entryPost)
    {
        makeControllerBuildPolicySuccess();
        auto emptyNames = std::unordered_set<base::Name> {};
        EXPECT_CALL(*m_mockPolicy, assets()).WillRepeatedly(::testing::ReturnRefOfCopy(emptyNames));
        auto error = m_router->addEntry(entryPost);
        EXPECT_TRUE(error.has_value());
    }

    void makeControllerPolicyAssetsSuccess()
    {
        makeControllerBuildPolicySuccess();
        auto assets = std::unordered_set<base::Name> {"asset/wazuh/0"};
        EXPECT_CALL(*m_mockPolicy, assets()).WillRepeatedly(::testing::ReturnRefOfCopy(assets));
    }

    void makeControllerNameFilterFailture(router::prod::EntryPost entryPost)
    {
        std::string hash = "hash";
        makeControllerPolicyAssetsSuccess();
        EXPECT_CALL(*m_mockControllerMaker, create(testing::_, testing::_, testing::_))
            .WillOnce(::testing::Return(m_mockController));
        auto emptyExpression = base::Expression {};
        EXPECT_CALL(*m_mockPolicy, expression()).WillOnce(::testing::ReturnRefOfCopy(emptyExpression));
        EXPECT_CALL(*m_mockPolicy, hash()).WillOnce(::testing::ReturnRefOfCopy(hash));
        stopControllerCall();
        auto error = m_router->addEntry(entryPost);
        EXPECT_TRUE(error.has_value());
    }

    void makeControllerNameFilterSuccess()
    {
        std::string hash = "hash";
        makeControllerPolicyAssetsSuccess();
        EXPECT_CALL(*m_mockControllerMaker, create(testing::_, testing::_, testing::_))
            .WillOnce(::testing::Return(m_mockController));

        auto emptyExpression = base::Expression {};
        EXPECT_CALL(*m_mockPolicy, expression()).WillOnce(::testing::ReturnRefOfCopy(emptyExpression));
        EXPECT_CALL(*m_mockPolicy, hash()).WillOnce(::testing::ReturnRefOfCopy(hash));
    }

    void makeControllerBuildAssetFailture(router::prod::EntryPost entryPost)
    {
        makeControllerNameFilterSuccess();
        EXPECT_CALL(*m_mockBuilder, buildAsset(testing::_))
            .WillOnce(::testing::Throw(std::runtime_error("Policy was not building")));
        stopControllerCall();
        auto error = m_router->addEntry(entryPost);
        EXPECT_TRUE(error.has_value());
    }

    bool addEntry(router::prod::EntryPost entryPost, bool stop = true)
    {
        makeControllerNameFilterSuccess();
        EXPECT_CALL(*m_mockBuilder, buildAsset(testing::_)).WillOnce(::testing::Return(base::Expression {}));

        auto error = m_router->addEntry(entryPost);
        if (stop)
        {
            stopControllerCall();
        }
        return !error.has_value();
    }

    void stopControllerCall(size_t times = 1) { EXPECT_CALL(*m_mockController, stop()).Times(times); }

    bool removeEntry(const std::string& name)
    {
        auto result = m_router->removeEntry(name);
        return !result.has_value();
    }

    bool rebuildEntry(const std::string& name)
    {
        auto result = m_router->rebuildEntry(name);
        return !result.has_value();
    }

    void rebuildEntryBuildPolicyFailture(const std::string& name)
    {
        EXPECT_CALL(*m_mockBuilder, buildPolicy(testing::_))
            .WillOnce(::testing::Throw(std::runtime_error("Policy was not building")));
        EXPECT_FALSE(rebuildEntry(name));
    }

    void rebuildEntryPolicyAssetsFailture(const std::string& name)
    {
        makeControllerBuildPolicySuccess();
        auto emptyNames = std::unordered_set<base::Name> {};
        EXPECT_CALL(*m_mockPolicy, assets()).WillRepeatedly(::testing::ReturnRefOfCopy(emptyNames));
        EXPECT_FALSE(rebuildEntry(name));
    }

    void rebuildEntryBuildAssetFailture(const std::string& name)
    {
        makeControllerNameFilterSuccess();
        EXPECT_CALL(*m_mockBuilder, buildAsset(testing::_))
            .WillOnce(::testing::Throw(std::runtime_error("Filter was not building")));
        stopControllerCall(2);
        EXPECT_FALSE(rebuildEntry(name));
    }

    bool enableEntry(const std::string& name)
    {
        auto result = m_router->enableEntry(name);
        return !result.has_value();
    }

    bool changePriority(const std::string& name, size_t priority)
    {
        auto result = m_router->changePriority(name, priority);
        return !result.has_value();
    }

    bool getEntry(const std::string& name)
    {
        auto result = m_router->getEntry(name);
        return !std::holds_alternative<base::Error>(result);
    }

    std::size_t getEntries()
    {
        auto result = m_router->getEntries();
        return result.size();
    }

    bool ingestEvent()
    {
        auto event = std::make_shared<json::Json>(R"({"key": "value"})");
        bool mockCalled = false;

        EXPECT_CALL(*m_mockController, ingest(testing::_))
            .WillOnce(testing::Invoke([&mockCalled]() { mockCalled = true; }));

        m_router->ingest(std::move(event));

        return mockCalled;
    }
};

TEST_F(RouterTest, AddEntryBadPolicyName)
{
    auto entryPost = router::prod::EntryPost {ENVIRONMENT_NAME, "POLICY_NAME", FILTER_NAME, PRIORITY};
    makeControllerNamePolicyFailture(entryPost);
}

TEST_F(RouterTest, AddEntryBuildPolicyError)
{
    auto entryPost = router::prod::EntryPost {ENVIRONMENT_NAME, POLICY_NAME, FILTER_NAME, PRIORITY};
    makeControllerBuildPolicyFailture(entryPost);
}

TEST_F(RouterTest, AddEntryPolicyAssetError)
{
    auto entryPost = router::prod::EntryPost {ENVIRONMENT_NAME, POLICY_NAME, FILTER_NAME, PRIORITY};
    makeControllerPolicyAssetsFailture(entryPost);
}

TEST_F(RouterTest, AddEntryBadFilterName)
{
    auto entryPost = router::prod::EntryPost {ENVIRONMENT_NAME, POLICY_NAME, "FILTER_NAME", PRIORITY};
    makeControllerNameFilterFailture(entryPost);
}

TEST_F(RouterTest, AddEntryBuildAssetError)
{
    auto entryPost = router::prod::EntryPost {ENVIRONMENT_NAME, POLICY_NAME, FILTER_NAME, PRIORITY};
    makeControllerBuildAssetFailture(entryPost);
}

TEST_F(RouterTest, AddEntrySucess)
{
    auto entryPost = router::prod::EntryPost {ENVIRONMENT_NAME, POLICY_NAME, FILTER_NAME, PRIORITY};

    auto result = addEntry(entryPost);
    EXPECT_TRUE(result);
}

TEST_F(RouterTest, AddEntrySameNameError)
{
    auto entryPost = router::prod::EntryPost {ENVIRONMENT_NAME, POLICY_NAME, FILTER_NAME, PRIORITY};
    auto result = addEntry(entryPost);
    EXPECT_TRUE(result);

    auto entryPostSameName = router::prod::EntryPost {ENVIRONMENT_NAME, POLICY_NAME, FILTER_NAME, PRIORITY + 1};
    result = addEntry(entryPostSameName);
    EXPECT_FALSE(result);
}

TEST_F(RouterTest, AddEntrySamePriority)
{
    auto entryPost = router::prod::EntryPost {ENVIRONMENT_NAME, POLICY_NAME, FILTER_NAME, PRIORITY};
    auto result = addEntry(entryPost);
    EXPECT_TRUE(result);

    auto entryPostSamePriority =
        router::prod::EntryPost {ENVIRONMENT_NAME + "mirror", POLICY_NAME, FILTER_NAME, PRIORITY};
    result = addEntry(entryPostSamePriority);
    EXPECT_FALSE(result);
}

TEST_F(RouterTest, RemoveEntryNameNotFound)
{
    EXPECT_FALSE(removeEntry(ENVIRONMENT_NAME));
}

TEST_F(RouterTest, RemoveEntrySuccess)
{
    auto entryPost = router::prod::EntryPost {ENVIRONMENT_NAME, POLICY_NAME, FILTER_NAME, PRIORITY};
    addEntry(entryPost);

    EXPECT_TRUE(removeEntry(ENVIRONMENT_NAME));
}

TEST_F(RouterTest, RebuildEntryNameNotFound)
{
    EXPECT_FALSE(rebuildEntry(ENVIRONMENT_NAME));
}

TEST_F(RouterTest, RebuildEntryBuildPolicyError)
{
    auto entryPost = router::prod::EntryPost {ENVIRONMENT_NAME, POLICY_NAME, FILTER_NAME, PRIORITY};
    addEntry(entryPost);

    rebuildEntryBuildPolicyFailture(ENVIRONMENT_NAME);
}

TEST_F(RouterTest, RebuildEntryBuildAssetError)
{
    auto entryPost = router::prod::EntryPost {ENVIRONMENT_NAME, POLICY_NAME, FILTER_NAME, PRIORITY};
    addEntry(entryPost, false);

    rebuildEntryBuildAssetFailture(ENVIRONMENT_NAME);
}

TEST_F(RouterTest, EnableEntryNameNotFound)
{
    EXPECT_FALSE(enableEntry(ENVIRONMENT_NAME));
}

TEST_F(RouterTest, EnableEntrySuccess)
{
    auto entryPost = router::prod::EntryPost {ENVIRONMENT_NAME, POLICY_NAME, FILTER_NAME, PRIORITY};
    addEntry(entryPost);

    EXPECT_TRUE(enableEntry(ENVIRONMENT_NAME));
}

TEST_F(RouterTest, ChangePriorityEqualZero)
{
    EXPECT_FALSE(changePriority(ENVIRONMENT_NAME, 0));
}

TEST_F(RouterTest, ChangePriorityNameNotFound)
{
    EXPECT_FALSE(changePriority(ENVIRONMENT_NAME, PRIORITY));
}

TEST_F(RouterTest, ChangePrioritySamePriority)
{
    auto entryPost = router::prod::EntryPost {ENVIRONMENT_NAME, POLICY_NAME, FILTER_NAME, PRIORITY};
    addEntry(entryPost);

    EXPECT_TRUE(changePriority(ENVIRONMENT_NAME, PRIORITY));
}

TEST_F(RouterTest, ChangePriorityAlreadyInUse)
{
    auto entryPost = router::prod::EntryPost {ENVIRONMENT_NAME, POLICY_NAME, FILTER_NAME, PRIORITY};
    addEntry(entryPost, false);

    auto entryPostOther = router::prod::EntryPost {ENVIRONMENT_NAME + "mirror", POLICY_NAME, FILTER_NAME, PRIORITY + 1};
    addEntry(entryPostOther, false);
    stopControllerCall(2);

    EXPECT_FALSE(changePriority(ENVIRONMENT_NAME, PRIORITY + 1));
}

TEST_F(RouterTest, GetEntryNameNotFound)
{
    EXPECT_FALSE(getEntry(ENVIRONMENT_NAME));
}

TEST_F(RouterTest, GetEntrySuccess)
{
    auto entryPost = router::prod::EntryPost {ENVIRONMENT_NAME, POLICY_NAME, FILTER_NAME, PRIORITY};
    addEntry(entryPost);

    EXPECT_TRUE(getEntry(ENVIRONMENT_NAME));
}

TEST_F(RouterTest, GetEntriesEmpty)
{
    EXPECT_TRUE(getEntries() == 0);
}

TEST_F(RouterTest, GetEntriesNotEmpty)
{
    auto entryPost = router::prod::EntryPost {ENVIRONMENT_NAME, POLICY_NAME, FILTER_NAME, PRIORITY};
    addEntry(entryPost, false);

    auto entryPostOther = router::prod::EntryPost {ENVIRONMENT_NAME + "mirror", POLICY_NAME, FILTER_NAME, PRIORITY + 1};
    addEntry(entryPostOther, false);
    stopControllerCall(2);

    EXPECT_TRUE(getEntries() == 2);
}

TEST_F(RouterTest, IngestSuccess)
{
    auto entryPost = router::prod::EntryPost {ENVIRONMENT_NAME, POLICY_NAME, FILTER_NAME, PRIORITY};
    addEntry(entryPost);

    enableEntry(ENVIRONMENT_NAME);

    EXPECT_TRUE(ingestEvent());
}
