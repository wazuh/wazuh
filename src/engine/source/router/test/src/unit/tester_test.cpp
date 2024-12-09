#include <gtest/gtest.h>

#include <bk/mockController.hpp>
#include <builder/mockBuilder.hpp>
#include <builder/mockPolicy.hpp>

#include "tester.hpp"

const std::string ENVIRONMENT_NAME = "Test";
const std::string POLICY_NAME = "policy/name/0";
const uint32_t LIFESPAM = 1234;

class TesterTest : public ::testing::Test
{
protected:
    std::shared_ptr<builder::mocks::MockBuilder> m_mockBuilder;
    std::shared_ptr<bk::mocks::MockMakerController> m_mockControllerMaker;
    std::shared_ptr<bk::mocks::MockController> m_mockController;
    std::shared_ptr<builder::mocks::MockPolicy> m_mockPolicy;
    std::shared_ptr<router::Tester> m_test;

public:
    void SetUp() override
    {
        m_mockBuilder = std::make_shared<builder::mocks::MockBuilder>();
        m_mockControllerMaker = std::make_shared<bk::mocks::MockMakerController>();
        m_mockController = std::make_shared<bk::mocks::MockController>();
        m_mockPolicy = std::make_shared<builder::mocks::MockPolicy>();
        auto environmentBuilder = std::make_shared<router::EnvironmentBuilder>(m_mockBuilder, m_mockControllerMaker);
        m_test = std::make_shared<router::Tester>(environmentBuilder);
    }

    void TearDown() override { m_test.reset(); }

    void addEntryCallers(const std::unordered_set<base::Name>& fakeAssets, const std::string& hash)
    {
        EXPECT_CALL(*m_mockBuilder, buildPolicy(testing::_)).WillOnce(::testing::Return(m_mockPolicy));
        EXPECT_CALL(*m_mockPolicy, assets()).WillRepeatedly(::testing::ReturnRefOfCopy(fakeAssets));
        EXPECT_CALL(*m_mockControllerMaker, create(testing::_, testing::_, testing::_))
            .WillOnce(::testing::Return(m_mockController));

        EXPECT_CALL(*m_mockPolicy, expression()).WillOnce(::testing::ReturnRefOfCopy(base::Expression {}));
        EXPECT_CALL(*m_mockPolicy, hash()).WillOnce(::testing::ReturnRef(hash));
    }

    void stopControllerCall(size_t times = 1) { EXPECT_CALL(*m_mockController, stop()).Times(times); }

    void rebuildEntryFailture()
    {
        EXPECT_CALL(*m_mockBuilder, buildPolicy(testing::_))
            .WillOnce(::testing::Throw(std::runtime_error("Policy was not building")));
    }

    void rebuildEntryCallersSuccess(const std::unordered_set<base::Name>& fakeAssets, const std::string& hash)
    {
        EXPECT_CALL(*m_mockBuilder, buildPolicy(testing::_)).WillOnce(::testing::Return(m_mockPolicy));
        EXPECT_CALL(*m_mockPolicy, assets()).WillRepeatedly(::testing::ReturnRefOfCopy(fakeAssets));
        EXPECT_CALL(*m_mockControllerMaker, create(testing::_, testing::_, testing::_))
            .WillOnce(::testing::Return(m_mockController));

        EXPECT_CALL(*m_mockPolicy, expression()).WillOnce(::testing::ReturnRefOfCopy(base::Expression {}));
        EXPECT_CALL(*m_mockPolicy, hash()).WillOnce(::testing::ReturnRef(hash));
    }

    void ingestTestCallersSuccess(const char* event)
    {
        EXPECT_CALL(*m_mockController, subscribe(testing::_, testing::_))
            .WillOnce(::testing::Return(bk::Subscription(1)));
        EXPECT_CALL(*m_mockController, ingestGet(testing::_))
            .WillOnce(::testing::Return(std::make_shared<json::Json>(event)));
        EXPECT_CALL(*m_mockController, unsubscribeAll());
    }

    void ingestTestCallersFailture()
    {
        EXPECT_CALL(*m_mockController, subscribe(testing::_, testing::_))
            .WillOnce(::testing::Return(base::Error {"error"}));
        EXPECT_CALL(*m_mockController, unsubscribeAll());
    }
};

TEST_F(TesterTest, AddEntryRepeatdly)
{
    auto entryPost = router::test::EntryPost {ENVIRONMENT_NAME, POLICY_NAME, LIFESPAM};
    const std::string hash = "hash";
    std::unordered_set<base::Name> fakeAssets {};
    fakeAssets.insert(base::Name("asset/test/0"));

    addEntryCallers(fakeAssets, hash);
    auto error = m_test->addEntry(entryPost);
    stopControllerCall();

    EXPECT_EQ(error, std::nullopt);

    addEntryCallers(fakeAssets, hash);
    error = m_test->addEntry(entryPost);
    stopControllerCall();

    EXPECT_STREQ(error.value().message.c_str(), "The name of the testing environment already exist");
}

TEST_F(TesterTest, AddEntrySuccess)
{
    auto entryPostOne = router::test::EntryPost {ENVIRONMENT_NAME, POLICY_NAME, LIFESPAM};
    const std::string hash = "hash";
    std::unordered_set<base::Name> fakeAssets {};
    fakeAssets.insert(base::Name("asset/test/0"));

    addEntryCallers(fakeAssets, hash);
    auto error = m_test->addEntry(entryPostOne);
    EXPECT_EQ(error, std::nullopt);

    auto entryPostTwo = router::test::EntryPost {ENVIRONMENT_NAME + "mirror", POLICY_NAME, LIFESPAM};

    addEntryCallers(fakeAssets, hash);
    error = m_test->addEntry(entryPostTwo);
    EXPECT_EQ(error, std::nullopt);

    stopControllerCall(2);
}

TEST_F(TesterTest, FailedCreatingEnvironment)
{
    auto entryPost = router::test::EntryPost {ENVIRONMENT_NAME, "decoder", LIFESPAM};

    auto error = m_test->addEntry(entryPost);

    EXPECT_TRUE(error.has_value());

    EXPECT_STREQ(error.value().message.c_str(),
                 "Failed to create the testing environment: The asset name is empty or it is not a policy");
}

TEST_F(TesterTest, FailedRemovingEnvironment)
{
    auto error = m_test->removeEntry(ENVIRONMENT_NAME);

    EXPECT_TRUE(error.has_value());

    EXPECT_STREQ(error.value().message.c_str(), "The testing environment not exist");
}

TEST_F(TesterTest, SuccessRemovingEnvironment)
{
    auto entryPostOne = router::test::EntryPost {ENVIRONMENT_NAME, POLICY_NAME, LIFESPAM};
    const std::string hash = "hash";
    std::unordered_set<base::Name> fakeAssets {};
    fakeAssets.insert(base::Name("asset/test/0"));

    addEntryCallers(fakeAssets, hash);
    m_test->addEntry(entryPostOne);
    stopControllerCall();

    auto error = m_test->removeEntry(ENVIRONMENT_NAME);

    EXPECT_FALSE(error.has_value());
}

TEST_F(TesterTest, FaildedRebuildingEnvironment)
{
    auto error = m_test->rebuildEntry(ENVIRONMENT_NAME);

    EXPECT_TRUE(error.has_value());

    EXPECT_STREQ(error.value().message.c_str(), "The testing environment not exist");
}

TEST_F(TesterTest, FaildedRebuildingEnvironmentMakeControllerError)
{
    auto entryPostOne = router::test::EntryPost {ENVIRONMENT_NAME, POLICY_NAME, LIFESPAM};
    std::unordered_set<base::Name> fakeAssets {};
    const std::string hash = "hash";
    fakeAssets.insert(base::Name("asset/test/0"));

    addEntryCallers(fakeAssets, hash);
    m_test->addEntry(entryPostOne);
    stopControllerCall();

    rebuildEntryFailture();
    auto error = m_test->rebuildEntry(ENVIRONMENT_NAME);

    EXPECT_TRUE(error.has_value());
    EXPECT_STREQ(error.value().message.c_str(), "Failed to create the testing environment: Policy was not building");
}

TEST_F(TesterTest, SuccessRebuildingEnvironment)
{
    auto entryPostOne = router::test::EntryPost {ENVIRONMENT_NAME, POLICY_NAME, LIFESPAM};
    std::unordered_set<base::Name> fakeAssets {};
    const std::string hash = "hash";
    fakeAssets.insert(base::Name("asset/test/0"));

    addEntryCallers(fakeAssets, hash);
    m_test->addEntry(entryPostOne);
    EXPECT_CALL(*m_mockController, stop());

    rebuildEntryCallersSuccess(fakeAssets, hash);
    auto error = m_test->rebuildEntry(ENVIRONMENT_NAME);

    EXPECT_FALSE(error.has_value());
}

TEST_F(TesterTest, FailedEnableEntry)
{
    auto error = m_test->enableEntry(ENVIRONMENT_NAME);

    EXPECT_TRUE(error.has_value());

    EXPECT_STREQ(error.value().message.c_str(), "The testing environment not exist");
}

TEST_F(TesterTest, SuccessEnableEntry)
{
    auto entryPostOne = router::test::EntryPost {ENVIRONMENT_NAME, POLICY_NAME, LIFESPAM};
    const std::string hash = "hash";
    std::unordered_set<base::Name> fakeAssets {};
    fakeAssets.insert(base::Name("asset/test/0"));

    addEntryCallers(fakeAssets, hash);
    m_test->addEntry(entryPostOne);
    stopControllerCall();

    auto error = m_test->enableEntry(ENVIRONMENT_NAME);

    EXPECT_FALSE(error.has_value());
}

TEST_F(TesterTest, SuccessGetEntries)
{
    auto entryPostOne = router::test::EntryPost {ENVIRONMENT_NAME, POLICY_NAME, LIFESPAM};
    const std::string hash = "hash";
    std::unordered_set<base::Name> fakeAssets {};
    fakeAssets.insert(base::Name("asset/test/0"));

    addEntryCallers(fakeAssets, hash);
    m_test->addEntry(entryPostOne);

    auto entryPostTwo = router::test::EntryPost {ENVIRONMENT_NAME + "mirror", POLICY_NAME, LIFESPAM};

    addEntryCallers(fakeAssets, hash);
    m_test->addEntry(entryPostTwo);

    stopControllerCall(2);

    EXPECT_EQ(m_test->getEntries().size(), 2);
}

TEST_F(TesterTest, FailtureGetEntry)
{
    auto error = m_test->getEntry(ENVIRONMENT_NAME);

    EXPECT_TRUE(std::holds_alternative<base::Error>(error));

    EXPECT_STREQ(std::get<base::Error>(error).message.c_str(), "The testing environment not exist");
}

TEST_F(TesterTest, SuccessGetEntry)
{
    auto entryPostOne = router::test::EntryPost {ENVIRONMENT_NAME, POLICY_NAME, LIFESPAM};
    std::unordered_set<base::Name> fakeAssets {};
    fakeAssets.insert(base::Name("asset/test/0"));
    addEntryCallers(fakeAssets, "");
    m_test->addEntry(entryPostOne);
    // EXPECT_CALL(*m_mockController, stop());

    // auto response = m_test->getEntry(ENVIRONMENT_NAME);

    // EXPECT_FALSE(std::holds_alternative<base::Error>(response));

    // EXPECT_STREQ(std::get<router::test::Entry>(response).name().c_str(), ENVIRONMENT_NAME.c_str());
}

TEST_F(TesterTest, SuccessIngestTest)
{
    auto entryPost = router::test::EntryPost {ENVIRONMENT_NAME, POLICY_NAME, LIFESPAM};
    const std::string hash = "hash";
    std::unordered_set<base::Name> fakeAssets {};
    fakeAssets.insert(base::Name("asset/test/0"));

    addEntryCallers(fakeAssets, hash);
    m_test->addEntry(entryPost);

    m_test->enableEntry(ENVIRONMENT_NAME);

    std::unordered_set<std::string> fakeAssetsString {};
    fakeAssetsString.insert("asset/test/0");
    router::test::Options opt(router::test::Options::TraceLevel::ASSET_ONLY, fakeAssetsString, ENVIRONMENT_NAME);
    auto event = R"({"key": "value"})";
    auto jsonEvent = std::make_shared<json::Json>(R"({"key": "value"})");

    ingestTestCallersSuccess(event);

    auto response = m_test->ingestTest(std::move(jsonEvent), opt);
    EXPECT_FALSE(std::holds_alternative<base::Error>(response));

    stopControllerCall();
}

TEST_F(TesterTest, FailtureIngestTestNameNotExist)
{
    std::unordered_set<std::string> fakeAssetsString {};
    fakeAssetsString.insert("asset/test/0");
    router::test::Options opt(router::test::Options::TraceLevel::ASSET_ONLY, fakeAssetsString, ENVIRONMENT_NAME);
    auto event = std::make_shared<json::Json>(R"({"key": "value"})");

    auto response = m_test->ingestTest(std::move(event), opt);
    EXPECT_TRUE(std::holds_alternative<base::Error>(response));
}

TEST_F(TesterTest, FailtureIngestTestNotEnabled)
{
    auto entryPost = router::test::EntryPost {ENVIRONMENT_NAME, POLICY_NAME, LIFESPAM};
    const std::string hash = "hash";
    std::unordered_set<base::Name> fakeAssets {};
    fakeAssets.insert(base::Name("asset/test/0"));

    addEntryCallers(fakeAssets, hash);
    m_test->addEntry(entryPost);

    std::unordered_set<std::string> fakeAssetsString {};
    fakeAssetsString.insert("asset/test/0");
    router::test::Options opt(router::test::Options::TraceLevel::ASSET_ONLY, fakeAssetsString, ENVIRONMENT_NAME);
    auto event = std::make_shared<json::Json>(R"({"key": "value"})");

    auto response = m_test->ingestTest(std::move(event), opt);
    EXPECT_TRUE(std::holds_alternative<base::Error>(response));

    stopControllerCall();
}

TEST_F(TesterTest, FailtureIngestTestNotSubscribe)
{
    auto entryPost = router::test::EntryPost {ENVIRONMENT_NAME, POLICY_NAME, LIFESPAM};
    const std::string hash = "hash";
    std::unordered_set<base::Name> fakeAssets {};
    fakeAssets.insert(base::Name("asset/test/0"));

    addEntryCallers(fakeAssets, hash);
    m_test->addEntry(entryPost);

    m_test->enableEntry(ENVIRONMENT_NAME);

    std::unordered_set<std::string> fakeAssetsString {};
    fakeAssetsString.insert("asset/test/0");
    router::test::Options opt(router::test::Options::TraceLevel::ASSET_ONLY, fakeAssetsString, ENVIRONMENT_NAME);
    auto event = std::make_shared<json::Json>(R"({"key": "value"})");

    ingestTestCallersFailture();

    auto response = m_test->ingestTest(std::move(event), opt);
    EXPECT_TRUE(std::holds_alternative<base::Error>(response));

    stopControllerCall();
}

TEST_F(TesterTest, FailtureGetAssetsNameNotExist)
{
    auto error = m_test->getAssets(ENVIRONMENT_NAME);

    EXPECT_TRUE(std::holds_alternative<base::Error>(error));

    EXPECT_STREQ(std::get<base::Error>(error).message.c_str(), "The testing environment not exist");
}

TEST_F(TesterTest, FailtureGetAssetsNameNotEnabled)
{
    auto entryPost = router::test::EntryPost {ENVIRONMENT_NAME, POLICY_NAME, LIFESPAM};
    const std::string hash = "hash";
    std::unordered_set<base::Name> fakeAssets {};
    fakeAssets.insert(base::Name("asset/test/0"));

    addEntryCallers(fakeAssets, hash);
    m_test->addEntry(entryPost);

    auto error = m_test->getAssets(ENVIRONMENT_NAME);

    EXPECT_TRUE(std::holds_alternative<base::Error>(error));

    EXPECT_STREQ(std::get<base::Error>(error).message.c_str(), "The testing environment is not builded");

    stopControllerCall();
}

TEST_F(TesterTest, SuccessGetAssets)
{
    auto entryPost = router::test::EntryPost {ENVIRONMENT_NAME, POLICY_NAME, LIFESPAM};
    const std::string hash = "hash";
    std::unordered_set<base::Name> fakeAssets {};
    fakeAssets.insert(base::Name("asset/test/0"));

    addEntryCallers(fakeAssets, hash);
    m_test->addEntry(entryPost);
    m_test->enableEntry(ENVIRONMENT_NAME);

    std::unordered_set<std::string> fakeAssetsString {};
    fakeAssetsString.insert("asset/test/0");
    EXPECT_CALL(*m_mockController, getTraceables()).WillOnce(::testing::ReturnRef(fakeAssetsString));
    auto error = m_test->getAssets(ENVIRONMENT_NAME);

    EXPECT_FALSE(std::holds_alternative<base::Error>(error));

    stopControllerCall();
}

TEST_F(TesterTest, FailtureUpdateLastUsedNameNotExist)
{
    EXPECT_FALSE(m_test->updateLastUsed(ENVIRONMENT_NAME));
}

TEST_F(TesterTest, SucessUpdateLast)
{
    auto entryPost = router::test::EntryPost {ENVIRONMENT_NAME, POLICY_NAME, LIFESPAM};
    const std::string hash = "hash";
    std::unordered_set<base::Name> fakeAssets {};
    fakeAssets.insert(base::Name("asset/test/0"));

    addEntryCallers(fakeAssets, hash);
    m_test->addEntry(entryPost);
    EXPECT_TRUE(m_test->updateLastUsed(ENVIRONMENT_NAME));

    stopControllerCall();
}
