#include <gtest/gtest.h>

#include <bk/mockController.hpp>
#include <builder/mockBuilder.hpp>
#include <builder/mockPolicy.hpp>

#include "tester.hpp"

const std::string ENVIRONMENT_NAME = "Test";
const cm::store::NamespaceId POLICY_NAMESPACE {"policy_name_0"};
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
        EXPECT_CALL(*m_mockBuilder, buildPolicy(testing::_, testing::_))
            .WillOnce(::testing::Return(m_mockPolicy));
        EXPECT_CALL(*m_mockPolicy, assets()).WillRepeatedly(::testing::ReturnRefOfCopy(fakeAssets));
        EXPECT_CALL(*m_mockControllerMaker, create(testing::_, testing::_, testing::_))
            .WillOnce(::testing::Return(m_mockController));

        EXPECT_CALL(*m_mockPolicy, expression()).WillOnce(::testing::ReturnRefOfCopy(base::Expression {}));
        EXPECT_CALL(*m_mockPolicy, hash()).WillOnce(::testing::ReturnRefOfCopy(hash));
    }

    void stopControllerCall(size_t times = 1) { EXPECT_CALL(*m_mockController, stop()).Times(times); }

    void rebuildEntryFailture()
    {
        EXPECT_CALL(*m_mockBuilder, buildPolicy(testing::_, testing::_))
            .WillOnce(::testing::Throw(std::runtime_error("Policy was not building")));
    }

    void rebuildEntryCallersSuccess(const std::unordered_set<base::Name>& fakeAssets, const std::string& hash)
    {
        EXPECT_CALL(*m_mockBuilder, buildPolicy(testing::_, testing::_))
            .WillOnce(::testing::Return(m_mockPolicy));
        EXPECT_CALL(*m_mockPolicy, assets()).WillRepeatedly(::testing::ReturnRefOfCopy(fakeAssets));
        EXPECT_CALL(*m_mockControllerMaker, create(testing::_, testing::_, testing::_))
            .WillOnce(::testing::Return(m_mockController));

        EXPECT_CALL(*m_mockPolicy, expression()).WillOnce(::testing::ReturnRefOfCopy(base::Expression {}));
        EXPECT_CALL(*m_mockPolicy, hash()).WillOnce(::testing::ReturnRefOfCopy(hash));
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
    auto entryPost = router::test::EntryPost {ENVIRONMENT_NAME, POLICY_NAMESPACE, LIFESPAM};
    const std::string hash = "hash";
    std::unordered_set<base::Name> fakeAssets {};
    fakeAssets.insert(base::Name("asset/test/0"));

    addEntryCallers(fakeAssets, hash);
    auto error = m_test->addEntry(entryPost, /*ignoreFail=*/false);
    stopControllerCall();

    EXPECT_EQ(error, std::nullopt);

    addEntryCallers(fakeAssets, hash);
    error = m_test->addEntry(entryPost, /*ignoreFail=*/false);
    stopControllerCall();

    EXPECT_STREQ(error.value().message.c_str(), "The 'Test' environment already exists.");
}

TEST_F(TesterTest, AddEntrySuccess)
{
    auto entryPostOne = router::test::EntryPost {ENVIRONMENT_NAME, POLICY_NAMESPACE, LIFESPAM};
    const std::string hash = "hash";
    std::unordered_set<base::Name> fakeAssets {};
    fakeAssets.insert(base::Name("asset/test/0"));

    addEntryCallers(fakeAssets, hash);
    auto error = m_test->addEntry(entryPostOne, /*ignoreFail=*/false);
    EXPECT_EQ(error, std::nullopt);

    auto entryPostTwo = router::test::EntryPost {ENVIRONMENT_NAME + "mirror", POLICY_NAMESPACE, LIFESPAM};

    addEntryCallers(fakeAssets, hash);
    error = m_test->addEntry(entryPostTwo, /*ignoreFail=*/false);
    EXPECT_EQ(error, std::nullopt);

    stopControllerCall(2);
}

TEST_F(TesterTest, FailedCreatingEnvironment)
{
    auto entryPost = router::test::EntryPost {ENVIRONMENT_NAME, cm::store::NamespaceId {"decoder"}, LIFESPAM};

    EXPECT_CALL(*m_mockBuilder, buildPolicy(testing::_, testing::_)).WillOnce(::testing::Return(nullptr));
    EXPECT_CALL(*m_mockControllerMaker, create(testing::_, testing::_, testing::_)).Times(0);

    auto error = m_test->addEntry(entryPost, /*ignoreFail=*/false);

    EXPECT_TRUE(error.has_value());

    EXPECT_STREQ(error.value().message.c_str(),
                 "Failed to create the testing environment: Failed to build policy 'decoder'");
}

TEST_F(TesterTest, FailedCreatingEnvironmentControllerNull)
{
    auto entryPost = router::test::EntryPost {ENVIRONMENT_NAME, POLICY_NAMESPACE, LIFESPAM};
    std::unordered_set<base::Name> fakeAssets {};
    fakeAssets.insert(base::Name("asset/test/0"));

    EXPECT_CALL(*m_mockBuilder, buildPolicy(testing::_, testing::_))
        .WillOnce(::testing::Return(m_mockPolicy));
    EXPECT_CALL(*m_mockPolicy, assets()).WillRepeatedly(::testing::ReturnRefOfCopy(fakeAssets));
    EXPECT_CALL(*m_mockPolicy, expression()).WillOnce(::testing::ReturnRefOfCopy(base::Expression {}));
    EXPECT_CALL(*m_mockControllerMaker, create(testing::_, testing::_, testing::_))
        .WillOnce(::testing::Return(nullptr));
    EXPECT_CALL(*m_mockPolicy, hash()).Times(0);

    auto error = m_test->addEntry(entryPost, /*ignoreFail=*/false);

    EXPECT_TRUE(error.has_value());
    EXPECT_STREQ(error.value().message.c_str(),
                 "Failed to create the testing environment: Failed to create controller for policy 'policy_name_0'");
}

TEST_F(TesterTest, FailedRemovingEnvironment)
{
    auto error = m_test->removeEntry(ENVIRONMENT_NAME);

    EXPECT_TRUE(error.has_value());

    EXPECT_STREQ(error.value().message.c_str(), "The 'Test' environment does not exist.");
}

TEST_F(TesterTest, SuccessRemovingEnvironment)
{
    auto entryPostOne = router::test::EntryPost {ENVIRONMENT_NAME, POLICY_NAMESPACE, LIFESPAM};
    const std::string hash = "hash";
    std::unordered_set<base::Name> fakeAssets {};
    fakeAssets.insert(base::Name("asset/test/0"));

    addEntryCallers(fakeAssets, hash);
    m_test->addEntry(entryPostOne, /*ignoreFail=*/false);
    stopControllerCall();

    auto error = m_test->removeEntry(ENVIRONMENT_NAME);

    EXPECT_FALSE(error.has_value());
}

TEST_F(TesterTest, FaildedRebuildingEnvironment)
{
    auto error = m_test->rebuildEntry(ENVIRONMENT_NAME);

    EXPECT_TRUE(error.has_value());

    EXPECT_STREQ(error.value().message.c_str(), "The 'Test' environment does not exist.");
}

TEST_F(TesterTest, FaildedRebuildingEnvironmentMakeControllerError)
{
    auto entryPostOne = router::test::EntryPost {ENVIRONMENT_NAME, POLICY_NAMESPACE, LIFESPAM};
    std::unordered_set<base::Name> fakeAssets {};
    const std::string hash = "hash";
    fakeAssets.insert(base::Name("asset/test/0"));

    addEntryCallers(fakeAssets, hash);
    m_test->addEntry(entryPostOne, /*ignoreFail=*/false);
    stopControllerCall();

    rebuildEntryFailture();
    auto error = m_test->rebuildEntry(ENVIRONMENT_NAME);

    EXPECT_TRUE(error.has_value());
    EXPECT_STREQ(error.value().message.c_str(), "Failed to create the 'Test' environment: Policy was not building");
}

TEST_F(TesterTest, SuccessRebuildingEnvironment)
{
    auto entryPostOne = router::test::EntryPost {ENVIRONMENT_NAME, POLICY_NAMESPACE, LIFESPAM};
    std::unordered_set<base::Name> fakeAssets {};
    const std::string hash = "hash";
    fakeAssets.insert(base::Name("asset/test/0"));

    addEntryCallers(fakeAssets, hash);
    m_test->addEntry(entryPostOne, /*ignoreFail=*/false);
    EXPECT_CALL(*m_mockController, stop());

    rebuildEntryCallersSuccess(fakeAssets, hash);
    auto error = m_test->rebuildEntry(ENVIRONMENT_NAME);

    EXPECT_FALSE(error.has_value());
}

TEST_F(TesterTest, FailedEnableEntry)
{
    auto error = m_test->enableEntry(ENVIRONMENT_NAME);

    EXPECT_TRUE(error.has_value());

    EXPECT_STREQ(error.value().message.c_str(), "The 'Test' environment does not exist.");
}

TEST_F(TesterTest, SuccessEnableEntry)
{
    auto entryPostOne = router::test::EntryPost {ENVIRONMENT_NAME, POLICY_NAMESPACE, LIFESPAM};
    const std::string hash = "hash";
    std::unordered_set<base::Name> fakeAssets {};
    fakeAssets.insert(base::Name("asset/test/0"));

    addEntryCallers(fakeAssets, hash);
    m_test->addEntry(entryPostOne, /*ignoreFail=*/false);
    stopControllerCall();

    auto error = m_test->enableEntry(ENVIRONMENT_NAME);

    EXPECT_FALSE(error.has_value());
}

TEST_F(TesterTest, SuccessGetEntries)
{
    auto entryPostOne = router::test::EntryPost {ENVIRONMENT_NAME, POLICY_NAMESPACE, LIFESPAM};
    const std::string hash = "hash";
    std::unordered_set<base::Name> fakeAssets {};
    fakeAssets.insert(base::Name("asset/test/0"));

    addEntryCallers(fakeAssets, hash);
    m_test->addEntry(entryPostOne, /*ignoreFail=*/false);

    auto entryPostTwo = router::test::EntryPost {ENVIRONMENT_NAME + "mirror", POLICY_NAMESPACE, LIFESPAM};

    addEntryCallers(fakeAssets, hash);
    m_test->addEntry(entryPostTwo, /*ignoreFail=*/false);

    stopControllerCall(2);

    EXPECT_EQ(m_test->getEntries().size(), 2);
}

TEST_F(TesterTest, FailtureGetEntry)
{
    auto error = m_test->getEntry(ENVIRONMENT_NAME);

    EXPECT_TRUE(std::holds_alternative<base::Error>(error));

    EXPECT_STREQ(std::get<base::Error>(error).message.c_str(), "The 'Test' environment does not exist.");
}

TEST_F(TesterTest, SuccessGetEntry)
{
    auto entryPostOne = router::test::EntryPost {ENVIRONMENT_NAME, POLICY_NAMESPACE, LIFESPAM};
    std::unordered_set<base::Name> fakeAssets {};
    fakeAssets.insert(base::Name("asset/test/0"));
    addEntryCallers(fakeAssets, "");
    m_test->addEntry(entryPostOne, /*ignoreFail=*/false);
    // EXPECT_CALL(*m_mockController, stop());

    // auto response = m_test->getEntry(ENVIRONMENT_NAME);

    // EXPECT_FALSE(std::holds_alternative<base::Error>(response));

    // EXPECT_STREQ(std::get<router::test::Entry>(response).name().c_str(), ENVIRONMENT_NAME.c_str());
}

TEST_F(TesterTest, SuccessIngestTest)
{
    auto entryPost = router::test::EntryPost {ENVIRONMENT_NAME, POLICY_NAMESPACE, LIFESPAM};
    const std::string hash = "hash";
    std::unordered_set<base::Name> fakeAssets {};
    fakeAssets.insert(base::Name("asset/test/0"));

    addEntryCallers(fakeAssets, hash);
    m_test->addEntry(entryPost, /*ignoreFail=*/false);

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
    auto entryPost = router::test::EntryPost {ENVIRONMENT_NAME, POLICY_NAMESPACE, LIFESPAM};
    const std::string hash = "hash";
    std::unordered_set<base::Name> fakeAssets {};
    fakeAssets.insert(base::Name("asset/test/0"));

    addEntryCallers(fakeAssets, hash);
    m_test->addEntry(entryPost, /*ignoreFail=*/false);

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
    auto entryPost = router::test::EntryPost {ENVIRONMENT_NAME, POLICY_NAMESPACE, LIFESPAM};
    const std::string hash = "hash";
    std::unordered_set<base::Name> fakeAssets {};
    fakeAssets.insert(base::Name("asset/test/0"));

    addEntryCallers(fakeAssets, hash);
    m_test->addEntry(entryPost, /*ignoreFail=*/false);

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

    EXPECT_STREQ(std::get<base::Error>(error).message.c_str(), "The 'Test' environment does not exist.");
}

TEST_F(TesterTest, FailtureGetAssetsNameNotEnabled)
{
    auto entryPost = router::test::EntryPost {ENVIRONMENT_NAME, POLICY_NAMESPACE, LIFESPAM};
    const std::string hash = "hash";
    std::unordered_set<base::Name> fakeAssets {};
    fakeAssets.insert(base::Name("asset/test/0"));

    addEntryCallers(fakeAssets, hash);
    m_test->addEntry(entryPost, /*ignoreFail=*/false);

    auto error = m_test->getAssets(ENVIRONMENT_NAME);

    EXPECT_TRUE(std::holds_alternative<base::Error>(error));

    EXPECT_STREQ(std::get<base::Error>(error).message.c_str(), "The 'Test' environment is not builded");

    stopControllerCall();
}

TEST_F(TesterTest, SuccessGetAssets)
{
    auto entryPost = router::test::EntryPost {ENVIRONMENT_NAME, POLICY_NAMESPACE, LIFESPAM};
    const std::string hash = "hash";
    std::unordered_set<base::Name> fakeAssets {};
    fakeAssets.insert(base::Name("asset/test/0"));

    addEntryCallers(fakeAssets, hash);
    m_test->addEntry(entryPost, /*ignoreFail=*/false);
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
    auto entryPost = router::test::EntryPost {ENVIRONMENT_NAME, POLICY_NAMESPACE, LIFESPAM};
    const std::string hash = "hash";
    std::unordered_set<base::Name> fakeAssets {};
    fakeAssets.insert(base::Name("asset/test/0"));

    addEntryCallers(fakeAssets, hash);
    m_test->addEntry(entryPost, /*ignoreFail=*/false);
    EXPECT_TRUE(m_test->updateLastUsed(ENVIRONMENT_NAME));

    stopControllerCall();
}

/**************************************************************************
 * renameEntry tests
 *************************************************************************/

TEST_F(TesterTest, RenameEntryFromNotExist)
{
    auto error = m_test->renameEntry("nonExistent", "newName");
    EXPECT_TRUE(error.has_value());
    EXPECT_STREQ(error.value().message.c_str(),
                 "Error renaming session: The 'nonExistent' environment does not exist");
}

TEST_F(TesterTest, RenameEntryToAlreadyExists)
{
    auto entryPostOne = router::test::EntryPost {ENVIRONMENT_NAME, POLICY_NAMESPACE, LIFESPAM};
    auto entryPostTwo = router::test::EntryPost {"Other", POLICY_NAMESPACE, LIFESPAM};
    const std::string hash = "hash";
    std::unordered_set<base::Name> fakeAssets {};
    fakeAssets.insert(base::Name("asset/test/0"));

    addEntryCallers(fakeAssets, hash);
    m_test->addEntry(entryPostOne, /*ignoreFail=*/false);

    addEntryCallers(fakeAssets, hash);
    m_test->addEntry(entryPostTwo, /*ignoreFail=*/false);

    auto error = m_test->renameEntry(ENVIRONMENT_NAME, "Other");
    EXPECT_TRUE(error.has_value());
    EXPECT_STREQ(error.value().message.c_str(), "Error renaming session: The 'Other' environment already exists");

    stopControllerCall(2);
}

TEST_F(TesterTest, RenameEntrySuccess)
{
    auto entryPost = router::test::EntryPost {ENVIRONMENT_NAME, POLICY_NAMESPACE, LIFESPAM};
    const std::string hash = "hash";
    std::unordered_set<base::Name> fakeAssets {};
    fakeAssets.insert(base::Name("asset/test/0"));

    addEntryCallers(fakeAssets, hash);
    m_test->addEntry(entryPost, /*ignoreFail=*/false);

    auto error = m_test->renameEntry(ENVIRONMENT_NAME, "Renamed");
    EXPECT_FALSE(error.has_value());

    // Verify old name no longer exists
    auto get = m_test->getEntry(ENVIRONMENT_NAME);
    EXPECT_TRUE(std::holds_alternative<base::Error>(get));

    // Verify new name exists
    get = m_test->getEntry("Renamed");
    EXPECT_FALSE(std::holds_alternative<base::Error>(get));

    stopControllerCall();
}

/**************************************************************************
 * addTrace coverage via ingestTest with subscriber callback invocation
 *************************************************************************/

TEST_F(TesterTest, IngestTestWithTraceAll)
{
    auto entryPost = router::test::EntryPost {ENVIRONMENT_NAME, POLICY_NAMESPACE, LIFESPAM};
    const std::string hash = "hash";
    std::unordered_set<base::Name> fakeAssets {};
    fakeAssets.insert(base::Name("asset/test/0"));

    addEntryCallers(fakeAssets, hash);
    m_test->addEntry(entryPost, /*ignoreFail=*/false);
    m_test->enableEntry(ENVIRONMENT_NAME);

    std::unordered_set<std::string> fakeAssetsString {};
    fakeAssetsString.insert("asset/test/0");
    router::test::Options opt(router::test::Options::TraceLevel::ALL, fakeAssetsString, ENVIRONMENT_NAME);

    bk::Subscriber capturedSub;
    EXPECT_CALL(*m_mockController, subscribe(testing::_, testing::_))
        .WillOnce(
            [&capturedSub](const std::string&, bk::Subscriber sub) -> base::RespOrError<bk::Subscription>
            {
                capturedSub = std::move(sub);
                return bk::Subscription(1);
            });

    auto event = R"({"key": "value"})";
    EXPECT_CALL(*m_mockController, ingestGet(testing::_))
        .WillOnce(
            [&capturedSub, &event](base::Event&&) -> base::Event
            {
                // Simulate trace callbacks during ingestion
                capturedSub("trace line 1", false);
                capturedSub("trace line 2", true);
                capturedSub("SUCCESS", true);
                capturedSub("", false); // empty trace - should be ignored
                return std::make_shared<json::Json>(event);
            });
    EXPECT_CALL(*m_mockController, unsubscribeAll());

    auto jsonEvent = std::make_shared<json::Json>(R"({"key": "value"})");
    auto response = m_test->ingestTest(std::move(jsonEvent), opt);
    EXPECT_FALSE(std::holds_alternative<base::Error>(response));

    auto& output = std::get<router::test::Output>(response);
    // Verify traces were collected
    EXPECT_FALSE(output.traceList().empty());

    stopControllerCall();
}

TEST_F(TesterTest, IngestTestWithTraceAssetOnly)
{
    auto entryPost = router::test::EntryPost {ENVIRONMENT_NAME, POLICY_NAMESPACE, LIFESPAM};
    const std::string hash = "hash";
    std::unordered_set<base::Name> fakeAssets {};
    fakeAssets.insert(base::Name("asset/test/0"));

    addEntryCallers(fakeAssets, hash);
    m_test->addEntry(entryPost, /*ignoreFail=*/false);
    m_test->enableEntry(ENVIRONMENT_NAME);

    std::unordered_set<std::string> fakeAssetsString {};
    fakeAssetsString.insert("asset/test/0");
    router::test::Options opt(router::test::Options::TraceLevel::ASSET_ONLY, fakeAssetsString, ENVIRONMENT_NAME);

    bk::Subscriber capturedSub;
    EXPECT_CALL(*m_mockController, subscribe(testing::_, testing::_))
        .WillOnce(
            [&capturedSub](const std::string&, bk::Subscriber sub) -> base::RespOrError<bk::Subscription>
            {
                capturedSub = std::move(sub);
                return bk::Subscription(1);
            });

    auto event = R"({"key": "value"})";
    EXPECT_CALL(*m_mockController, ingestGet(testing::_))
        .WillOnce(
            [&capturedSub, &event](base::Event&&) -> base::Event
            {
                // With ASSET_ONLY, non-SUCCESS traces should NOT be stored
                capturedSub("some trace detail", false);
                capturedSub("SUCCESS", true);
                return std::make_shared<json::Json>(event);
            });
    EXPECT_CALL(*m_mockController, unsubscribeAll());

    auto jsonEvent = std::make_shared<json::Json>(R"({"key": "value"})");
    auto response = m_test->ingestTest(std::move(jsonEvent), opt);
    EXPECT_FALSE(std::holds_alternative<base::Error>(response));

    auto& output = std::get<router::test::Output>(response);
    // Traces should have the asset entry but only SUCCESS marker, no detailed traces
    EXPECT_FALSE(output.traceList().empty());

    stopControllerCall();
}

TEST_F(TesterTest, UpdateLastUsedWithExplicitTimestamp)
{
    auto entryPost = router::test::EntryPost {ENVIRONMENT_NAME, POLICY_NAMESPACE, LIFESPAM};
    const std::string hash = "hash";
    std::unordered_set<base::Name> fakeAssets {};
    fakeAssets.insert(base::Name("asset/test/0"));

    addEntryCallers(fakeAssets, hash);
    m_test->addEntry(entryPost, /*ignoreFail=*/false);
    EXPECT_TRUE(m_test->updateLastUsed(ENVIRONMENT_NAME, 12345));

    stopControllerCall();
}
