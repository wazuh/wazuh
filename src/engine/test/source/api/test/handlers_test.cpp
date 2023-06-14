#include <api/test/sessionManager.hpp>
#include <api/test/handlers.hpp>
#include <builders/baseHelper.hpp>
#include <cmds/src/defaultSettings.hpp>
#include <regex>

#include <gtest/gtest.h>
#include <mocks/store.hpp>
#include <mocks/fakeMetric.hpp>

#include <register.hpp>
#include <schemf/mocks/emptySchema.hpp>
#include <testsCommon.hpp>

using namespace api::test::handlers;
using namespace api::sessionManager;
const std::string rCommand {"dummy cmd"};
const std::string rOrigin {"Dummy org module"};
constexpr auto SIZE_QUEUE {100};
auto EXECUTION_NUMBER {0};
constexpr auto ASSET_PATH {"test/source/api/test/assets/"};
constexpr auto ROUTER_TABLE {"internal/router_table/0"};
constexpr auto JSON_DECODER {"decoder/core-hostinfo/0"};
constexpr auto JSON_FILTER {"filter/allow-all/0"};
constexpr auto JSON_DUMMY_FILTER {"filter/dummy_filter/0"};
constexpr auto JSON_DUMMY_POLICY {"policy/dummy_policy/0"};
constexpr auto JSON_POLICY {"policy/wazuh/0"};
constexpr auto JSON_INTEGRATION {"integration/wazuh-core/0"};
constexpr auto JSON_SCHEMA_ASSET {"schema/wazuh-asset/0"};
constexpr auto JSON_SCHEMA_POLICY {"schema/wazuh-policy/0"};

std::string readJsonFile(const std::string& filePath)
{
    std::ifstream jsonFile(filePath);

    if (!jsonFile.is_open())
    {
        return "";
    }

    std::stringstream buffer;
    buffer << jsonFile.rdbuf();

    jsonFile.close();

    return buffer.str();
}

base::Expression coutOutputHelper(const std::string& targetField,
                                  const std::string& rawName,
                                  const std::vector<std::string>& rawParameters,
                                  std::shared_ptr<defs::IDefinitions> definitions)
{
    const auto parameters = helper::base::processParameters(rawName, rawParameters, definitions);

    const auto name = helper::base::formatHelperName(rawName, targetField, parameters);
    // Return Term
    return base::Term<base::EngineOp>::create(
        name,
        [=, targetField = std::move(targetField), parameter = std::move(parameters)](
            base::Event event) -> base::result::Result<base::Event>
        {
            std::cout << "Dummy output: " << event->str() << std::endl;
            event->setString("dummyBypass", targetField);
            return base::result::makeSuccess(event, "Ok from dummy output");
        });
}

std::shared_ptr<builder::Builder> fakeBuilder(std::shared_ptr<MockStore> store)
{
    auto registry = std::make_shared<builder::internals::Registry<builder::internals::Builder>>();
    auto helperRegistry = std::make_shared<builder::internals::Registry<builder::internals::HelperBuilder>>();
    builder::internals::dependencies dependencies;
    dependencies.helperRegistry = helperRegistry;
    dependencies.logparDebugLvl = 0;
    dependencies.schema = schemf::mocks::EmptySchema::create();
    builder::internals::registerHelperBuilders(helperRegistry);
    builder::internals::registerBuilders(registry, dependencies);

    helperRegistry->registerBuilder(coutOutputHelper, "coutOutputHelper_test");

    auto builder = std::make_shared<builder::Builder>(store, registry);

    return builder;
};

class TestSessionDeleteCommand : public ::testing::TestWithParam<std::tuple<std::string, std::string>>
{
protected:
    api::Handler m_cmdAPI;
    std::shared_ptr<api::catalog::Catalog> m_spCatalog;
    std::shared_ptr<::router::Router> m_spRouter;
    std::shared_ptr<MockStore> m_spMockStore;
    std::shared_ptr<builder::Builder> m_spMockeBuilder;
    std::tuple<std::string, std::string, std::string, std::string, std::string, std::string> m_paths;

    void SetUp() override
    {
        initLogging();
        m_spMockStore = std::make_shared<MockStore>();
        m_spMockeBuilder = fakeBuilder(m_spMockStore);

        std::filesystem::path currentPath = std::filesystem::current_path();

        while (!currentPath.empty())
        {
            if (currentPath.filename() == "engine")
            {
                break;
            }

            currentPath = currentPath.parent_path();
        }

        auto absolutePath = currentPath / ASSET_PATH;
        auto pathrouterTable = absolutePath / ROUTER_TABLE;
        auto pathPolicy = absolutePath  / JSON_POLICY;
        auto pathDecoder = absolutePath  / JSON_DECODER;
        auto pathFilter = absolutePath  / JSON_FILTER;
        auto pathIntegration = absolutePath  / JSON_INTEGRATION;
        auto pathWazuhAsset = absolutePath  / JSON_SCHEMA_ASSET;
        auto pathWazuhPolicy = absolutePath  / JSON_SCHEMA_POLICY;
        auto pathDummyFilter = absolutePath  / JSON_DUMMY_FILTER;
        auto pathDummyPolicy = absolutePath  / JSON_DUMMY_POLICY;

        m_paths = std::make_tuple(pathFilter, pathIntegration, pathPolicy, pathDecoder, pathDummyFilter, pathDummyPolicy);

        EXPECT_CALL(*m_spMockStore, get(testing::_))
        .WillRepeatedly(testing::Invoke(
            [&](const base::Name& name)
            {
                if (name == ROUTER_TABLE)
                {
                    return json::Json {readJsonFile(pathrouterTable).c_str()};
                }
                else if (name == JSON_FILTER)
                {
                    return json::Json {readJsonFile(pathFilter).c_str()};
                }
                else
                {
                    // Handle other cases or return a default value
                    return json::Json {};
                }
            }));

        m_spRouter = std::make_shared<::router::Router>(m_spMockeBuilder, m_spMockStore);
        api::catalog::Config catalogConfig
        {
            m_spMockStore,
            m_spMockeBuilder,
            fmt::format("schema{}wazuh-asset{}0", base::Name::SEPARATOR_S, base::Name::SEPARATOR_S),
            fmt::format("schema{}wazuh-policy{}0", base::Name::SEPARATOR_S, base::Name::SEPARATOR_S)
        };
        
        auto eventQueue = std::make_shared<base::queue::ConcurrentQueue<base::Event>>(
                SIZE_QUEUE, std::make_shared<FakeMetricScope>(), std::make_shared<FakeMetricScope>());
        m_spRouter->run(eventQueue);

        EXPECT_CALL(*m_spMockStore, get(testing::_))
        .WillRepeatedly(testing::Invoke(
            [&](const base::Name& name)
            {
                if (name == JSON_SCHEMA_ASSET)
                {
                    return json::Json {readJsonFile(pathWazuhAsset).c_str()};
                }
                else if (name == JSON_SCHEMA_POLICY)
                {
                    return json::Json {readJsonFile(pathWazuhPolicy).c_str()};
                }
                else
                {
                    // Handle other cases or return a default value
                    return json::Json {};
                }
            }));

        m_spCatalog = std::make_shared<api::catalog::Catalog>(catalogConfig);
    }

    static void TearDownTestCase()
    {
        EXECUTION_NUMBER = 0;
    }
};

TEST_P(TestSessionDeleteCommand, Functionality)
{
    auto [sessionDeleteParams, outputSessionDelete] = GetParam();

    auto numTest {3};

    int executionNumber = ++EXECUTION_NUMBER;

    const auto expectedData = json::Json {outputSessionDelete.c_str()};

    if (executionNumber > (numTest - 1))
    {
        EXPECT_CALL(*m_spMockStore, get(testing::_))
            .WillRepeatedly(testing::Invoke(
                [&](const base::Name& name)
                {
                    if (name == JSON_FILTER)
                    {
                        return json::Json {readJsonFile(std::get<0>(m_paths)).c_str()};
                    }
                    if (name == JSON_DUMMY_FILTER)
                    {
                        return json::Json {readJsonFile(std::get<4>(m_paths)).c_str()};
                    }
                    else if (name == JSON_INTEGRATION)
                    {
                        return json::Json {readJsonFile(std::get<1>(m_paths)).c_str()};
                    }
                    else if (name == JSON_POLICY)
                    {
                        return json::Json {readJsonFile(std::get<2>(m_paths)).c_str()};
                    }
                    else if (name == JSON_DUMMY_POLICY)
                    {
                        return json::Json {readJsonFile(std::get<5>(m_paths)).c_str()};
                    }
                    else if (name == JSON_DECODER)
                    {
                        return json::Json {readJsonFile(std::get<3>(m_paths)).c_str()};
                    }
                    else
                    {
                        // Handle other cases or return a default value
                        return json::Json {};
                    }
                }));

        EXPECT_CALL(*m_spMockStore, add(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));
        EXPECT_CALL(*m_spMockStore, update(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));

        ASSERT_NO_THROW(m_cmdAPI = sessionPost(m_spCatalog, m_spRouter, m_spMockStore));
        json::Json sessionPostCommandparams {R"({"name":"dummy"})"};
        base::utils::wazuhProtocol::WazuhRequest request;
        ASSERT_NO_THROW(request = api::wpRequest::create(rCommand, rOrigin, sessionPostCommandparams));
        auto response = m_cmdAPI(request);
        EXPECT_TRUE(response.isValid());
        EXPECT_EQ(response.error(), 0);
        EXPECT_FALSE(response.message().has_value());
    }

    EXPECT_CALL(*m_spMockStore, del(testing::_)).WillRepeatedly(testing::Return(std::nullopt));
    EXPECT_CALL(*m_spMockStore, update(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));

    ASSERT_NO_THROW(m_cmdAPI = sessionsDelete(m_spCatalog, m_spRouter, m_spMockStore));
    json::Json sessionDeleteCommandparams {sessionDeleteParams.c_str()};
    base::utils::wazuhProtocol::WazuhRequest request;
    ASSERT_NO_THROW(request = api::wpRequest::create(rCommand, rOrigin, sessionDeleteCommandparams));
    auto response = m_cmdAPI(request);

    EXPECT_TRUE(response.isValid());
    EXPECT_EQ(response.error(), 0);
    EXPECT_FALSE(response.message().has_value());
    EXPECT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                            << "Expected: " << expectedData.prettyStr() << std::endl;

    m_spRouter->stop();
}

INSTANTIATE_TEST_SUITE_P(
    Functionality,
    TestSessionDeleteCommand,
    ::testing::Values(std::make_tuple(R"({})", R"({
                        "status": "ERROR",
                        "error": "Missing both /name and /delete_all fields, at least one field must be set"
                    })"),
                      std::make_tuple(R"({"name":"dummy"})", R"({
                        "status": "ERROR",
                        "error": "Session 'dummy' could not be found"
                    })"),
                    std::make_tuple(R"({"name":"dummy"})", R"({
                        "status": "OK"
                    })")));

class TestSessionListCommand : public ::testing::TestWithParam<std::tuple<std::string, std::string>>
{
protected:
    api::Handler m_cmdAPI;
    std::shared_ptr<api::catalog::Catalog> m_spCatalog;
    std::shared_ptr<::router::Router> m_spRouter;
    std::shared_ptr<MockStore> m_spMockStore;
    std::shared_ptr<builder::Builder> m_spMockeBuilder;
    std::tuple<std::string, std::string, std::string, std::string, std::string, std::string> m_paths;

    void SetUp() override
    {
        initLogging();
        m_spMockStore = std::make_shared<MockStore>();
        m_spMockeBuilder = fakeBuilder(m_spMockStore);

        std::filesystem::path currentPath = std::filesystem::current_path();

        while (!currentPath.empty())
        {
            if (currentPath.filename() == "engine")
            {
                break;
            }

            currentPath = currentPath.parent_path();
        }

        auto absolutePath = currentPath / ASSET_PATH;
        auto pathrouterTable = absolutePath / ROUTER_TABLE;
        auto pathPolicy = absolutePath  / JSON_POLICY;
        auto pathDecoder = absolutePath  / JSON_DECODER;
        auto pathFilter = absolutePath  / JSON_FILTER;
        auto pathIntegration = absolutePath  / JSON_INTEGRATION;
        auto pathWazuhAsset = absolutePath  / JSON_SCHEMA_ASSET;
        auto pathWazuhPolicy = absolutePath  / JSON_SCHEMA_POLICY;
        auto pathDummyFilter = absolutePath  / JSON_DUMMY_FILTER;
        auto pathDummyPolicy = absolutePath  / JSON_DUMMY_POLICY;

        m_paths = std::make_tuple(pathFilter, pathIntegration, pathPolicy, pathDecoder, pathDummyFilter, pathDummyPolicy);

        EXPECT_CALL(*m_spMockStore, get(testing::_))
        .WillRepeatedly(testing::Invoke(
            [&](const base::Name& name)
            {
                if (name == ROUTER_TABLE)
                {
                    return json::Json {readJsonFile(pathrouterTable).c_str()};
                }
                else if (name == JSON_FILTER)
                {
                    return json::Json {readJsonFile(pathFilter).c_str()};
                }
                else
                {
                    // Handle other cases or return a default value
                    return json::Json {};
                }
            }));

        m_spRouter = std::make_shared<::router::Router>(m_spMockeBuilder, m_spMockStore);
        api::catalog::Config catalogConfig
        {
            m_spMockStore,
            m_spMockeBuilder,
            fmt::format("schema{}wazuh-asset{}0", base::Name::SEPARATOR_S, base::Name::SEPARATOR_S),
            fmt::format("schema{}wazuh-policy{}0", base::Name::SEPARATOR_S, base::Name::SEPARATOR_S)
        };
        
        auto eventQueue = std::make_shared<base::queue::ConcurrentQueue<base::Event>>(
                SIZE_QUEUE, std::make_shared<FakeMetricScope>(), std::make_shared<FakeMetricScope>());
        m_spRouter->run(eventQueue);

        EXPECT_CALL(*m_spMockStore, get(testing::_))
        .WillRepeatedly(testing::Invoke(
            [&](const base::Name& name)
            {
                if (name == JSON_SCHEMA_ASSET)
                {
                    return json::Json {readJsonFile(pathWazuhAsset).c_str()};
                }
                else if (name == JSON_SCHEMA_POLICY)
                {
                    return json::Json {readJsonFile(pathWazuhPolicy).c_str()};
                }
                else
                {
                    // Handle other cases or return a default value
                    return json::Json {};
                }
            }));

        m_spCatalog = std::make_shared<api::catalog::Catalog>(catalogConfig);
    }

    static void TearDownTestCase()
    {
        EXECUTION_NUMBER = 0;
    }
};

TEST_P(TestSessionListCommand, Functionality)
{
    auto [sessionListParams, outputSessionList] = GetParam();

    int executionNumber = ++EXECUTION_NUMBER;

    json::Json tmp;

    EXPECT_CALL(*m_spMockStore, get(testing::_))
        .WillRepeatedly(testing::Invoke(
            [&](const base::Name& name)
            {
                if (name == JSON_FILTER)
                {
                    return json::Json {readJsonFile(std::get<0>(m_paths)).c_str()};
                }
                if (name == JSON_DUMMY_FILTER)
                {
                    return json::Json {readJsonFile(std::get<4>(m_paths)).c_str()};
                }
                else if (name == JSON_INTEGRATION)
                {
                    return json::Json {readJsonFile(std::get<1>(m_paths)).c_str()};
                }
                else if (name == JSON_POLICY)
                {
                    return json::Json {readJsonFile(std::get<2>(m_paths)).c_str()};
                }
                else if (name == JSON_DUMMY_POLICY)
                {
                    return json::Json {readJsonFile(std::get<5>(m_paths)).c_str()};
                }
                else if (name == JSON_DECODER)
                {
                    return json::Json {readJsonFile(std::get<3>(m_paths)).c_str()};
                }
                else
                {
                    // Handle other cases or return a default value
                    return json::Json {};
                }
            }));

    EXPECT_CALL(*m_spMockStore, add(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));
    EXPECT_CALL(*m_spMockStore, update(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));

    ASSERT_NO_THROW(m_cmdAPI = sessionPost(m_spCatalog, m_spRouter, m_spMockStore));
    json::Json sessionPostCommandparams {R"({"name":"dummy"})"};
    base::utils::wazuhProtocol::WazuhRequest request;
    ASSERT_NO_THROW(request = api::wpRequest::create(rCommand, rOrigin, sessionPostCommandparams));
    auto response = m_cmdAPI(request);
    EXPECT_TRUE(response.isValid());
    EXPECT_EQ(response.error(), 0);
    EXPECT_FALSE(response.message().has_value());

    // check response
    const auto expectedData = json::Json {outputSessionList.c_str()};

    if (executionNumber > 1)
    {
        ASSERT_NO_THROW(m_cmdAPI = sessionsGet());
        json::Json sessionListCommandparams {sessionListParams.c_str()};
        base::utils::wazuhProtocol::WazuhRequest requestGet;
        ASSERT_NO_THROW(requestGet = api::wpRequest::create(rCommand, rOrigin, sessionListCommandparams));
        response = m_cmdAPI(requestGet);
        EXPECT_TRUE(response.isValid());
        EXPECT_EQ(response.error(), 0);
        EXPECT_FALSE(response.message().has_value());
        EXPECT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                            << "Expected: " << expectedData.prettyStr() << std::endl;
    }
    else
    {
        ASSERT_NO_THROW(m_cmdAPI = sessionGet());
        json::Json sessionListCommandparams {sessionListParams.c_str()};
        base::utils::wazuhProtocol::WazuhRequest requestGet;
        ASSERT_NO_THROW(requestGet = api::wpRequest::create(rCommand, rOrigin, sessionListCommandparams));
        response = m_cmdAPI(requestGet);
        EXPECT_TRUE(response.isValid());
        EXPECT_EQ(response.error(), 0);
        EXPECT_FALSE(response.message().has_value());

        tmp = json::Json {response.toString().c_str()};
        tmp.erase("/data/creation_date");
        tmp.erase("/data/id");
        EXPECT_EQ(tmp, expectedData) << "Response: " << tmp.prettyStr() << std::endl
                                            << "Expected: " << expectedData.prettyStr() << std::endl;
    }
    
    EXPECT_CALL(*m_spMockStore, del(testing::_)).WillRepeatedly(testing::Return(std::nullopt));
    EXPECT_CALL(*m_spMockStore, update(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));
    
    ASSERT_NO_THROW(m_cmdAPI = sessionsDelete(m_spCatalog, m_spRouter, m_spMockStore));
    json::Json sessionsDeleteCommandparams {R"({"delete_all":true})"};
    base::utils::wazuhProtocol::WazuhRequest requestDelete;
    ASSERT_NO_THROW(requestDelete = api::wpRequest::create(rCommand, rOrigin, sessionsDeleteCommandparams));
    response = m_cmdAPI(requestDelete);
    EXPECT_TRUE(response.isValid());
    EXPECT_EQ(response.error(), 0);
    EXPECT_FALSE(response.message().has_value());

    m_spRouter->stop();
}

INSTANTIATE_TEST_SUITE_P(
    Functionality,
    TestSessionListCommand,
    ::testing::Values(std::make_tuple(R"({"name":"dummy"})", R"({
            "data": {
                "status": "OK",
                "policy": "policy/dummy_policy/0",
                "filter": "filter/dummy_filter/0",
                "route": "dummy_route",
                "lifespan": 0,
                "description": ""
            },
            "error": 0
        })"),
        std::make_tuple(R"({})", R"({
            "status": "OK",
            "list": [
                "dummy"
            ]
        })")));

class TestSessionPostCommand : public ::testing::TestWithParam<std::tuple<std::string, std::string>>
{
protected:
    api::Handler m_cmdAPI;
    std::shared_ptr<api::catalog::Catalog> m_spCatalog;
    std::shared_ptr<::router::Router> m_spRouter;
    std::shared_ptr<MockStore> m_spMockStore;
    std::shared_ptr<builder::Builder> m_spMockeBuilder;
    std::tuple<std::string, std::string, std::string, std::string, std::string, std::string> m_paths;

    void SetUp() override
    {
        initLogging();
        m_spMockStore = std::make_shared<MockStore>();
        m_spMockeBuilder = fakeBuilder(m_spMockStore);

        std::filesystem::path currentPath = std::filesystem::current_path();

        while (!currentPath.empty())
        {
            if (currentPath.filename() == "engine")
            {
                break;
            }

            currentPath = currentPath.parent_path();
        }

        auto absolutePath = currentPath / ASSET_PATH;
        auto pathrouterTable = absolutePath / ROUTER_TABLE;
        auto pathPolicy = absolutePath  / JSON_POLICY;
        auto pathDecoder = absolutePath  / JSON_DECODER;
        auto pathFilter = absolutePath  / JSON_FILTER;
        auto pathIntegration = absolutePath  / JSON_INTEGRATION;
        auto pathWazuhAsset = absolutePath  / JSON_SCHEMA_ASSET;
        auto pathWazuhPolicy = absolutePath  / JSON_SCHEMA_POLICY;
        auto pathDummyFilter = absolutePath  / JSON_DUMMY_FILTER;
        auto pathDummyPolicy = absolutePath  / JSON_DUMMY_POLICY;

        m_paths = std::make_tuple(pathFilter, pathIntegration, pathPolicy, pathDecoder, pathDummyFilter, pathDummyPolicy);

        EXPECT_CALL(*m_spMockStore, get(testing::_))
        .WillRepeatedly(testing::Invoke(
            [&](const base::Name& name)
            {
                if (name == ROUTER_TABLE)
                {
                    return json::Json {readJsonFile(pathrouterTable).c_str()};
                }
                else if (name == JSON_FILTER)
                {
                    return json::Json {readJsonFile(pathFilter).c_str()};
                }
                else
                {
                    // Handle other cases or return a default value
                    return json::Json {};
                }
            }));

        m_spRouter = std::make_shared<::router::Router>(m_spMockeBuilder, m_spMockStore);
        api::catalog::Config catalogConfig
        {
            m_spMockStore,
            m_spMockeBuilder,
            fmt::format("schema{}wazuh-asset{}0", base::Name::SEPARATOR_S, base::Name::SEPARATOR_S),
            fmt::format("schema{}wazuh-policy{}0", base::Name::SEPARATOR_S, base::Name::SEPARATOR_S)
        };
        
        auto eventQueue = std::make_shared<base::queue::ConcurrentQueue<base::Event>>(
                SIZE_QUEUE, std::make_shared<FakeMetricScope>(), std::make_shared<FakeMetricScope>());
        m_spRouter->run(eventQueue);

        EXPECT_CALL(*m_spMockStore, get(testing::_))
        .WillRepeatedly(testing::Invoke(
            [&](const base::Name& name)
            {
                if (name == JSON_SCHEMA_ASSET)
                {
                    return json::Json {readJsonFile(pathWazuhAsset).c_str()};
                }
                else if (name == JSON_SCHEMA_POLICY)
                {
                    return json::Json {readJsonFile(pathWazuhPolicy).c_str()};
                }
                else
                {
                    // Handle other cases or return a default value
                    return json::Json {};
                }
            }));

        m_spCatalog = std::make_shared<api::catalog::Catalog>(catalogConfig);
    }

    static void TearDownTestCase()
    {
        EXECUTION_NUMBER = 0;
    }
};

TEST_P(TestSessionPostCommand, Functionality)
{
    auto [sessionPostParams, outputSessionPost] = GetParam();

    auto numTest {3};

    int executionNumber = ++EXECUTION_NUMBER;

    if (executionNumber > 1)
    {
        EXPECT_CALL(*m_spMockStore, get(testing::_))
            .WillRepeatedly(testing::Invoke(
                [&](const base::Name& name)
                {
                    if (name == JSON_FILTER)
                    {
                        return json::Json {readJsonFile(std::get<0>(m_paths)).c_str()};
                    }
                    if (name == JSON_DUMMY_FILTER)
                    {
                        return json::Json {readJsonFile(std::get<4>(m_paths)).c_str()};
                    }
                    else if (name == JSON_INTEGRATION)
                    {
                        return json::Json {readJsonFile(std::get<1>(m_paths)).c_str()};
                    }
                    else if (name == JSON_POLICY)
                    {
                        return json::Json {readJsonFile(std::get<2>(m_paths)).c_str()};
                    }
                    else if (name == JSON_DUMMY_POLICY)
                    {
                        return json::Json {readJsonFile(std::get<5>(m_paths)).c_str()};
                    }
                    else if (name == JSON_DECODER)
                    {
                        return json::Json {readJsonFile(std::get<3>(m_paths)).c_str()};
                    }
                    else
                    {
                        // Handle other cases or return a default value
                        return json::Json {};
                    }
                }));

        EXPECT_CALL(*m_spMockStore, add(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));
        EXPECT_CALL(*m_spMockStore, update(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));
    }

    ASSERT_NO_THROW(m_cmdAPI = sessionPost(m_spCatalog, m_spRouter, m_spMockStore));
    json::Json sessionPostCommandparams {sessionPostParams.c_str()};
    base::utils::wazuhProtocol::WazuhRequest request;
    ASSERT_NO_THROW(request = api::wpRequest::create(rCommand, rOrigin, sessionPostCommandparams));
    auto response = m_cmdAPI(request);

    // check response
    const auto expectedData = json::Json {outputSessionPost.c_str()};

    EXPECT_TRUE(response.isValid());
    EXPECT_EQ(response.error(), 0);
    EXPECT_FALSE(response.message().has_value());
    EXPECT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                            << "Expected: " << expectedData.prettyStr() << std::endl;
    
    if (executionNumber == numTest)
    {
        EXPECT_CALL(*m_spMockStore, del(testing::_)).WillRepeatedly(testing::Return(std::nullopt));
        EXPECT_CALL(*m_spMockStore, update(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));
        
        ASSERT_NO_THROW(m_cmdAPI = sessionsDelete(m_spCatalog, m_spRouter, m_spMockStore));
        json::Json sessionsDeleteCommandparams {R"({"delete_all":true})"};
        base::utils::wazuhProtocol::WazuhRequest requestDelete;
        ASSERT_NO_THROW(requestDelete = api::wpRequest::create(rCommand, rOrigin, sessionsDeleteCommandparams));
        auto response = m_cmdAPI(requestDelete);
        EXPECT_TRUE(response.isValid());
        EXPECT_EQ(response.error(), 0);
        EXPECT_FALSE(response.message().has_value());
    }

    m_spRouter->stop();
}

INSTANTIATE_TEST_SUITE_P(
    Functionality,
    TestSessionPostCommand,
    ::testing::Values(std::make_tuple(R"({})", R"({"status":"ERROR","error":"Missing /name field"})"),
                      std::make_tuple(R"({"name":"dummy"})", R"({
                        "status": "OK"
                    })"),
                    std::make_tuple(R"({"name":"dummy"})", R"({
                        "status": "ERROR",
                        "error": "Session 'dummy' already exists"
                    })")));

class TestRunCommand : public ::testing::TestWithParam<std::tuple<std::string, std::string>>
{
protected:
    api::Handler m_cmdAPI;

    void SetUp() override
    {
        initLogging();
    }
};

TEST_P(TestRunCommand, CheckParameters)
{
    auto [input, output] = GetParam();

    ASSERT_NO_THROW(m_cmdAPI = runPost(nullptr));
    json::Json params {input.c_str()};
    base::utils::wazuhProtocol::WazuhRequest request;
    ASSERT_NO_THROW(request = api::wpRequest::create(rCommand, rOrigin, params));
    auto response = m_cmdAPI(request);

    // check response
    const auto expectedData = json::Json {output.c_str()};

    // check response
    EXPECT_TRUE(response.isValid());
    EXPECT_EQ(response.error(), 0);
    EXPECT_FALSE(response.message().has_value());
    EXPECT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                             << "Expected: " << expectedData.prettyStr() << std::endl;
}

INSTANTIATE_TEST_SUITE_P(
    CheckParameters,
    TestRunCommand,
    ::testing::Values(std::make_tuple(R"({})", R"({"status":"ERROR","error":"Missing /name field"})"),
                      std::make_tuple(R"({"name":"dummy"})", R"({"status":"ERROR","error":"Missing /event field"})")));

class TestRunCommandIntegration : public ::testing::TestWithParam<std::tuple<std::string, std::string, std::string>>
{
protected:
    api::Handler m_cmdAPI;
    std::shared_ptr<api::catalog::Catalog> m_spCatalog;
    std::shared_ptr<::router::Router> m_spRouter;
    std::shared_ptr<MockStore> m_spMockStore;
    std::shared_ptr<builder::Builder> m_spMockeBuilder;
    std::tuple<std::string, std::string, std::string, std::string, std::string, std::string> m_paths;

    void SetUp() override
    {
        initLogging();
        m_spMockStore = std::make_shared<MockStore>();
        m_spMockeBuilder = fakeBuilder(m_spMockStore);

        std::filesystem::path currentPath = std::filesystem::current_path();

        while (!currentPath.empty())
        {
            if (currentPath.filename() == "engine")
            {
                break;
            }

            currentPath = currentPath.parent_path();
        }

        auto absolutePath = currentPath / ASSET_PATH;
        auto pathrouterTable = absolutePath / ROUTER_TABLE;
        auto pathPolicy = absolutePath  / JSON_POLICY;
        auto pathDecoder = absolutePath  / JSON_DECODER;
        auto pathFilter = absolutePath  / JSON_FILTER;
        auto pathIntegration = absolutePath  / JSON_INTEGRATION;
        auto pathWazuhAsset = absolutePath  / JSON_SCHEMA_ASSET;
        auto pathWazuhPolicy = absolutePath  / JSON_SCHEMA_POLICY;
        auto pathDummyFilter = absolutePath  / JSON_DUMMY_FILTER;
        auto pathDummyPolicy = absolutePath  / JSON_DUMMY_POLICY;

        m_paths = std::make_tuple(pathFilter, pathIntegration, pathPolicy, pathDecoder, pathDummyFilter, pathDummyPolicy);

        EXPECT_CALL(*m_spMockStore, get(testing::_))
        .WillRepeatedly(testing::Invoke(
            [&](const base::Name& name)
            {
                if (name == ROUTER_TABLE)
                {
                    return json::Json {readJsonFile(pathrouterTable).c_str()};
                }
                else if (name == JSON_FILTER)
                {
                    return json::Json {readJsonFile(pathFilter).c_str()};
                }
                else
                {
                    // Handle other cases or return a default value
                    return json::Json {};
                }
            }));

        m_spRouter = std::make_shared<::router::Router>(m_spMockeBuilder, m_spMockStore);
        api::catalog::Config catalogConfig
        {
            m_spMockStore,
            m_spMockeBuilder,
            fmt::format("schema{}wazuh-asset{}0", base::Name::SEPARATOR_S, base::Name::SEPARATOR_S),
            fmt::format("schema{}wazuh-policy{}0", base::Name::SEPARATOR_S, base::Name::SEPARATOR_S)
        };
        
        auto eventQueue = std::make_shared<base::queue::ConcurrentQueue<base::Event>>(
                SIZE_QUEUE, std::make_shared<FakeMetricScope>(), std::make_shared<FakeMetricScope>());
        m_spRouter->run(eventQueue);

        EXPECT_CALL(*m_spMockStore, get(testing::_))
        .WillRepeatedly(testing::Invoke(
            [&](const base::Name& name)
            {
                if (name == JSON_SCHEMA_ASSET)
                {
                    return json::Json {readJsonFile(pathWazuhAsset).c_str()};
                }
                else if (name == JSON_SCHEMA_POLICY)
                {
                    return json::Json {readJsonFile(pathWazuhPolicy).c_str()};
                }
                else
                {
                    // Handle other cases or return a default value
                    return json::Json {};
                }
            }));

        m_spCatalog = std::make_shared<api::catalog::Catalog>(catalogConfig);
    }
    
    static void TearDownTestCase()
    {
        EXECUTION_NUMBER = 0;
    }
};

TEST_P(TestRunCommandIntegration, Functionality)
{
    auto [runPostParams, sessionPostParams, outputRunPost] = GetParam();

    int executionNumber = ++EXECUTION_NUMBER;

    if (executionNumber > 1)
    {
        EXPECT_CALL(*m_spMockStore, get(testing::_))
            .WillRepeatedly(testing::Invoke(
                [&](const base::Name& name)
                {
                    if (name == JSON_FILTER)
                    {
                        return json::Json {readJsonFile(std::get<0>(m_paths)).c_str()};
                    }
                    if (name == JSON_DUMMY_FILTER)
                    {
                        return json::Json {readJsonFile(std::get<4>(m_paths)).c_str()};
                    }
                    else if (name == JSON_INTEGRATION)
                    {
                        return json::Json {readJsonFile(std::get<1>(m_paths)).c_str()};
                    }
                    else if (name == JSON_POLICY)
                    {
                        return json::Json {readJsonFile(std::get<2>(m_paths)).c_str()};
                    }
                    else if (name == JSON_DUMMY_POLICY)
                    {
                        return json::Json {readJsonFile(std::get<5>(m_paths)).c_str()};
                    }
                    else if (name == JSON_DECODER)
                    {
                        return json::Json {readJsonFile(std::get<3>(m_paths)).c_str()};
                    }
                    else
                    {
                        // Handle other cases or return a default value
                        return json::Json {};
                    }
                }));

        EXPECT_CALL(*m_spMockStore, add(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));
        EXPECT_CALL(*m_spMockStore, update(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));

        ASSERT_NO_THROW(m_cmdAPI = sessionPost(m_spCatalog, m_spRouter, m_spMockStore));
        json::Json sessionPostCommandparams {sessionPostParams.c_str()};
        base::utils::wazuhProtocol::WazuhRequest request;
        ASSERT_NO_THROW(request = api::wpRequest::create(rCommand, rOrigin, sessionPostCommandparams));
        auto response = m_cmdAPI(request);
        EXPECT_TRUE(response.isValid());
        EXPECT_EQ(response.error(), 0);
        EXPECT_FALSE(response.message().has_value());
    }

    ASSERT_NO_THROW(m_cmdAPI = runPost(m_spRouter));
    json::Json runPostCommandparams {runPostParams.c_str()};
    base::utils::wazuhProtocol::WazuhRequest request;
    ASSERT_NO_THROW(request = api::wpRequest::create(rCommand, rOrigin, runPostCommandparams));
    auto response = m_cmdAPI(request);

    // check response
    const auto expectedData = json::Json {outputRunPost.c_str()};

    // check response
    EXPECT_TRUE(response.isValid());
    EXPECT_EQ(response.error(), 0);
    EXPECT_FALSE(response.message().has_value());
    EXPECT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                             << "Expected: " << expectedData.prettyStr() << std::endl;

    EXPECT_CALL(*m_spMockStore, del(testing::_)).WillRepeatedly(testing::Return(std::nullopt));
    EXPECT_CALL(*m_spMockStore, update(testing::_, testing::_)).WillRepeatedly(testing::Return(std::nullopt));
    
    ASSERT_NO_THROW(m_cmdAPI = sessionsDelete(m_spCatalog, m_spRouter, m_spMockStore));
    json::Json sessionsDeleteCommandparams {R"({"delete_all":true})"};
    base::utils::wazuhProtocol::WazuhRequest requestDelete;
    ASSERT_NO_THROW(requestDelete = api::wpRequest::create(rCommand, rOrigin, sessionsDeleteCommandparams));
    response = m_cmdAPI(requestDelete);
    EXPECT_TRUE(response.isValid());
    EXPECT_EQ(response.error(), 0);
    EXPECT_FALSE(response.message().has_value());

    m_spRouter->stop();
}

INSTANTIATE_TEST_SUITE_P(
    Functionality,
    TestRunCommandIntegration,
    ::testing::Values(std::make_tuple(R"({"name":"dummy", "event":"hello world!"})", R"({"name":"dummy"})", R"({"status":"ERROR","error":"Session 'dummy' could not be found"})"),
                      std::make_tuple(R"({"name":"dummy", "event":"hello world!"})", R"({"name":"dummy"})", R"({
                        "status": "OK",
                        "output": {
                            "wazuh": {
                                "message": "hello world!",
                                "location": "api.test",
                                "queue": 49
                            },
                            "~TestSessionName": "dummy"
                        }
                    })"),
                    std::make_tuple(R"({"name":"dummy", "event":"hello world!", "debug_mode":1})", R"({"name":"dummy"})", R"({
                        "status": "OK",
                        "output": {
                            "~TestSessionName": "dummy",
                            "wazuh": {
                                "location": "api.test",
                                "message": "hello world!",
                                "queue": 49
                            }
                        },
                        "traces": {
                            "decoder": {
                                "core-hostinfo": [
                                    "failure"
                                ]
                            }
                        }
                    })"),
                    std::make_tuple(R"({"name":"dummy", "event":"hello world!", "debug_mode":2})", R"({"name":"dummy"})", R"({
                        "status": "OK",
                        "output": {
                            "~TestSessionName": "dummy",
                            "wazuh": {
                                "location": "api.test",
                                "queue": 49,
                                "message": "hello world!"
                            }
                        },
                        "traces": {
                            "decoder": {
                                "core-hostinfo": [
                                    "[decoder/core-hostinfo/0] [condition.value[/wazuh/queue==51]] -> Failure[decoder/core-hostinfo/0] [condition]:failure"
                                ]
                            }
                        }
                    })")));
