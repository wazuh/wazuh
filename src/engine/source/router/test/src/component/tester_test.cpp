#include <gtest/gtest.h>

#include <builder/register.hpp>
#include <logpar/registerParsers.hpp>

#include <bk/mockController.hpp>
#include <queue/mockQueue.hpp>
#include <schemf/mockSchema.hpp>
#include <kvdb/mockKvdbManager.hpp>
#include <wdb/mockWdbManager.hpp>
#include <sockiface/mockSockFactory.hpp>
#include <store/mockStore.hpp>

#include <router/orchestrator.hpp>

#include "fakeStore.hpp"

constexpr auto SERVER_API_TIMEOUT {100000};
constexpr auto NUM_THREADS {1};

void inline initLogging(void)
{
    static bool initialized = false;

    if (!initialized)
    {
        // Logging setup
        logging::LoggingConfig logConfig;
        logConfig.logLevel = "off";
        logConfig.filePath = "";
        logging::loggingInit(logConfig);
        initialized = true;
    }
}

class OrchestratorTesterTest : public ::testing::Test
{
protected:
    std::shared_ptr<builder::internals::Registry<builder::internals::Builder>> m_registry;
    std::shared_ptr<hlp::logpar::Logpar> m_logpar;

    std::shared_ptr<store::mocks::MockStore> m_mockStore;
    std::shared_ptr<bk::mocks::MockMakerController> m_mockControllerMaker;
    std::shared_ptr<bk::mocks::MockController> m_mockController;
    std::shared_ptr<queue::mocks::MockQueue<base::Event>> m_mockQueueRouter;
    std::shared_ptr<queue::mocks::MockQueue<router::test::QueueType>> m_mockQueueTester;
    std::shared_ptr<schemf::mocks::MockSchema> m_mockSchema;

    std::shared_ptr<router::Orchestrator> m_orchestrator;

public:
    void SetUp() override
    {
        initLogging();

        m_mockStore = std::make_shared<store::mocks::MockStore>();
        m_mockControllerMaker = std::make_shared<bk::mocks::MockMakerController>();
        m_mockController = std::make_shared<bk::mocks::MockController>();
        m_mockQueueRouter = std::make_shared<queue::mocks::MockQueue<base::Event>>();
        m_mockQueueTester = std::make_shared<queue::mocks::MockQueue<router::test::QueueType>>();
        m_mockSchema = std::make_shared<schemf::mocks::MockSchema>();
        m_logpar = std::make_shared<hlp::logpar::Logpar>(json::Json {WAZUH_LOGPAR_TYPES_JSON}, m_mockSchema);
        hlp::registerParsers(m_logpar);

        // Builder and registry
        {
            m_registry = std::make_shared<builder::internals::Registry<builder::internals::Builder>>();
            builder::internals::dependencies deps;
            deps.logparDebugLvl = 0;
            deps.logpar = m_logpar;
            deps.kvdbScopeName = "builder";
            deps.kvdbManager = std::make_shared<kvdb::mocks::MockKVDBManager>();
            deps.helperRegistry = std::make_shared<builder::internals::Registry<builder::internals::HelperBuilder>>();
            deps.schema = m_mockSchema;
            deps.forceFieldNaming = false;
            deps.sockFactory = std::make_shared<sockiface::mocks::MockSockFactory>();
            deps.wdbManager =
                std::make_shared<MockWdbManager>();
            builder::internals::registerHelperBuilders(deps.helperRegistry, deps);
            builder::internals::registerBuilders(m_registry, deps);
        }

        router::Orchestrator::Options config {.m_numThreads = NUM_THREADS,
                                              .m_wStore = m_mockStore,
                                              .m_wRegistry = m_registry,
                                              .m_controllerMaker = m_mockControllerMaker,
                                              .m_prodQueue = m_mockQueueRouter,
                                              .m_testQueue = m_mockQueueTester,
                                              .m_testTimeout = SERVER_API_TIMEOUT};

        EXPECT_CALL(*m_mockStore, readInternalDoc(testing::_))
            .WillRepeatedly(testing::Invoke(
                [&](const base::Name& name)
                {
                    if (name == "router/router/0")
                    {
                        return json::Json {ROUTER_JSON};
                    }
                    else if (name == "router/tester/0")
                    {
                        return json::Json {TESTER_JSON};
                    }
                    else if (name == "policy/wazuh/0")
                    {
                        // Handle other cases or return a default value
                        return json::Json {POLICY_JSON};
                    }
                    else
                    {
                        return json::Json {};
                    }
                }));

        EXPECT_CALL(*m_mockStore, readDoc(testing::_))
            .WillRepeatedly(testing::Invoke(
                [&](const base::Name& name)
                {
                    if (name == "integration/wazuh-core-fake/0")
                    {
                        return json::Json {INTEGRATION_JSON};
                    }
                    else if (name == "decoder/fake/0")
                    {
                        return json::Json {DECODER_JSON};
                    }
                    else
                    {
                        return json::Json {};
                    }
                }));

        EXPECT_CALL(*m_mockSchema, hasField(testing::_)).WillRepeatedly(testing::Return(true));
        EXPECT_CALL(*m_mockStore, getNamespace(testing::_)).WillRepeatedly(testing::Return(store::NamespaceId("system")));
        auto json = json::Json {R"({})"};
        json.setString("I am an fake decoder");
        EXPECT_CALL(*m_mockSchema, validate(testing::_, json)).WillRepeatedly(testing::Return(std::nullopt));
        EXPECT_CALL(*m_mockControllerMaker, create()).WillRepeatedly(testing::Return(m_mockController));
        EXPECT_CALL(*m_mockController, build(testing::_, testing::_)).WillRepeatedly(::testing::Return());

        m_orchestrator = std::make_shared<router::Orchestrator>(config);

        EXPECT_CALL(*m_mockQueueTester, tryPop(testing::_)).WillRepeatedly(testing::Return(true));
        EXPECT_CALL(*m_mockQueueRouter, waitPop(testing::_, testing::_)).WillRepeatedly(testing::Return(false));
        m_orchestrator->start();
    }
};

TEST_F(OrchestratorTesterTest, AddTestEntry)
{
    router::test::EntryPost entry("test", "policy/wazuh/0", 0);

    EXPECT_CALL(*m_mockStore, upsertInternalDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));

    EXPECT_FALSE(m_orchestrator->postTestEntry(entry).has_value());

    EXPECT_CALL(*m_mockController, stop()).Times(1);
    m_orchestrator->stop();
}

TEST_F(OrchestratorTesterTest, AddMultipleTestEntry)
{
    router::test::EntryPost entry("test", "policy/wazuh/0", 0);
    router::test::EntryPost entryTwo("testTwo", "policy/wazuh/0", 0);

    EXPECT_CALL(*m_mockStore, upsertInternalDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));

    EXPECT_FALSE(m_orchestrator->postTestEntry(entry).has_value());
    EXPECT_FALSE(m_orchestrator->postTestEntry(entryTwo).has_value());

    EXPECT_CALL(*m_mockController, stop()).Times(2);
    m_orchestrator->stop();
}

TEST_F(OrchestratorTesterTest, AddEqualTestEntry)
{
    router::test::EntryPost entry("test", "policy/wazuh/0", 0);

    EXPECT_CALL(*m_mockStore, upsertInternalDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));

    EXPECT_FALSE(m_orchestrator->postTestEntry(entry).has_value());
    EXPECT_CALL(*m_mockController, stop()).Times(1);
    EXPECT_TRUE(m_orchestrator->postTestEntry(entry).has_value());

    EXPECT_CALL(*m_mockController, stop()).Times(1);
    m_orchestrator->stop();
}

TEST_F(OrchestratorTesterTest, DeleteTestEntryWithoutName)
{
    EXPECT_CALL(*m_mockStore, upsertInternalDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));

    EXPECT_TRUE(m_orchestrator->deleteEntry("").has_value());

    m_orchestrator->stop();
}

TEST_F(OrchestratorTesterTest, DeleteTestEntry)
{
    router::test::EntryPost entry("test", "policy/wazuh/0", 0);

    EXPECT_CALL(*m_mockStore, upsertInternalDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));

    EXPECT_FALSE(m_orchestrator->postTestEntry(entry).has_value());
    EXPECT_CALL(*m_mockController, stop()).Times(1);

    EXPECT_FALSE(m_orchestrator->deleteTestEntry("test").has_value());

    m_orchestrator->stop();
}


TEST_F(OrchestratorTesterTest, DeleteTheEqualTestEntryTwoTimes)
{
    router::test::EntryPost entry("test", "policy/wazuh/0", 0);

    EXPECT_CALL(*m_mockStore, upsertInternalDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));

    EXPECT_FALSE(m_orchestrator->postTestEntry(entry).has_value());
    EXPECT_CALL(*m_mockController, stop()).Times(1);

    EXPECT_FALSE(m_orchestrator->deleteTestEntry("test").has_value());

    EXPECT_TRUE(m_orchestrator->deleteTestEntry("test").has_value());

    m_orchestrator->stop();
}

TEST_F(OrchestratorTesterTest, GetTestEntryWithoutName)
{
    EXPECT_CALL(*m_mockStore, upsertInternalDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));

    EXPECT_TRUE(base::isError(m_orchestrator->getEntry("")));

    m_orchestrator->stop();
}

TEST_F(OrchestratorTesterTest, GetTestEntry)
{
    router::test::EntryPost entry("test", "policy/wazuh/0", 0);
    router::test::EntryPost entryTwo("testTwo", "policy/wazuh/0", 0);

    EXPECT_CALL(*m_mockStore, upsertInternalDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));

    EXPECT_FALSE(m_orchestrator->postTestEntry(entry).has_value());
    EXPECT_FALSE(m_orchestrator->postTestEntry(entryTwo).has_value());

    EXPECT_CALL(*m_mockController, stop()).Times(2);

    EXPECT_STREQ(base::getResponse(m_orchestrator->getTestEntry("test")).name().c_str(), entry.name().c_str());
    EXPECT_STREQ(base::getResponse(m_orchestrator->getTestEntry("testTwo")).name().c_str(), entryTwo.name().c_str());

    m_orchestrator->stop();
}

TEST_F(OrchestratorTesterTest, ReloadTestEntryWithoutName)
{
    EXPECT_CALL(*m_mockStore, upsertInternalDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));

    EXPECT_TRUE(base::isError(m_orchestrator->reloadTestEntry("")));

    m_orchestrator->stop();
}

TEST_F(OrchestratorTesterTest, ReloadTestEntry)
{
    router::test::EntryPost entry("test", "policy/wazuh/0", 0);

    EXPECT_CALL(*m_mockStore, upsertInternalDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));

    EXPECT_FALSE(m_orchestrator->postTestEntry(entry).has_value());
    EXPECT_CALL(*m_mockController, stop()).Times(1);

    EXPECT_FALSE(m_orchestrator->reloadTestEntry("test").has_value());

    m_orchestrator->stop();
}

TEST_F(OrchestratorTesterTest, GetAssetsTestEntryError)
{
    EXPECT_CALL(*m_mockStore, upsertInternalDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));

    EXPECT_TRUE(base::isError(m_orchestrator->getAssets("test")));

    m_orchestrator->stop();
}

TEST_F(OrchestratorTesterTest, GetAssetsTestEntry)
{
    router::test::EntryPost entry("test", "policy/wazuh/0", 0);

    EXPECT_CALL(*m_mockStore, upsertInternalDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));

    EXPECT_FALSE(m_orchestrator->postTestEntry(entry).has_value());
    EXPECT_CALL(*m_mockController, stop()).Times(1);

    auto mockAsset = std::unordered_set<std::string> {"decoder/fake/0"};
    EXPECT_CALL(*m_mockController, getTraceables()).WillOnce(::testing::ReturnRef(mockAsset));
    auto assets = m_orchestrator->getAssets("test");
    EXPECT_FALSE(base::isError(assets));

    auto asset = base::getResponse(assets);
    EXPECT_FALSE(asset.empty());
    EXPECT_TRUE(asset.find("decoder/fake/0") != asset.end());

    m_orchestrator->stop();
}

TEST_F(OrchestratorTesterTest, IngestTest)
{
    router::test::EntryPost entry("test", "policy/wazuh/0", 0);

    EXPECT_CALL(*m_mockStore, upsertInternalDoc(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));

    EXPECT_FALSE(m_orchestrator->postTestEntry(entry).has_value());
    EXPECT_CALL(*m_mockController, stop()).Times(1);

    std::unordered_set<std::string> fakeAssetsString {};
    fakeAssetsString.insert("decoder/fake/0");
    router::test::Options opt(router::test::Options::TraceLevel::ASSET_ONLY, fakeAssetsString, "test");

    EXPECT_CALL(*m_mockQueueTester, tryPush(testing::_)).WillOnce(testing::Return(true));
    EXPECT_CALL(*m_mockQueueRouter, empty()).WillOnce(testing::Return(true));
    EXPECT_CALL(*m_mockQueueRouter, push(testing::_)).Times(1);

    auto resultFuture = m_orchestrator->ingestTest("1:any:message", opt);

    m_orchestrator->stop();
}
