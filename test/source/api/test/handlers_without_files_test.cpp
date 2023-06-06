#include <api/test/handlers.hpp>
#include <builders/baseHelper.hpp>
#include <filesystem>
#include <gtest/gtest.h>
#include <mocks/fakeMetric.hpp>
#include <mocks/store.hpp>
#include <register.hpp>
#include <schemf/mocks/emptySchema.hpp>
#include <testsCommon.hpp>
#include <cmds/src/defaultSettings.hpp>

using namespace api::test::handlers;
const std::string rCommand {"dummy cmd"};
const std::string rOrigin {"Dummy org module"};

// Route
constexpr auto ROUTE_TABLE_CONTENT_FORMAT =
    R"([
        {{
            "name": "{}",
            "priority": 50,
            "filter": "{}",
            "target": "{}"
        }}
    ])";

constexpr auto ROUTE_TABLE_NAME = "internal/router_table/0";
constexpr auto ROUTE_NAME_FORMAT = "{}_route";          ///< Route name format, where '{}' is the session name

// Filter
constexpr auto FILTER_CONTENT_FORMAT =
    R"({{"name": "{}"}})"; ///< Filter content format, where '{}' is the session
                                                                  ///< name
constexpr auto FILTER_NAME_FORMAT = "filter/test-{}/0"; ///< Filter name format, where '{}' is the session name

// Decoder
constexpr auto DECODER_CONTENT_FORMAT =
    R"({{
        "check": [
            {{
                "wazuh.queue": 51
            }}
        ],
        "name": "{}",
        "normalize": [
            {{
                "map": [
                    {{
                        "wazuh.decoders": "+array_append/core-hostinfo"
                    }}
                ]
            }}
        ]
    }})";

constexpr auto DECODER_NAME_FORMAT = "decoder/test-{}/0"; ///< Decoder name format, where '{}' is the session name

// Policy
constexpr auto POLICY_CONTENT_FORMAT = 
    R"({{
        "name": "{}",
        "integrations": [
            "{}"
        ]
    }})";
// TODO: The name of the session should appear, but since it is not implemented yet, it is left hardcoded
constexpr auto POLICY_NAME_FORMAT = "policy/test_env_A1/0"; ///< Policy name format, where '{}' is the session name

// Integration
constexpr auto INTEGRATION_CONTENT_FORMAT = 
    R"({{
        "decoders": [
            "{}"
        ],
        "filters": [
            "{}"
        ],
        "name": "{}"
    }})";
constexpr auto INTEGRATION_NAME_FORMAT = "integration/test-{}/0"; ///< Integration name format, where '{}' is the session name

struct FakeSession
{    
    FakeSession(const std::string& sessionName)
    {
        // Filter
        m_filterName = fmt::format(FILTER_NAME_FORMAT, sessionName);
        m_filterContent = fmt::format(FILTER_CONTENT_FORMAT, m_filterName, sessionName);

        // Decoder
        m_decoderName = fmt::format(DECODER_NAME_FORMAT, sessionName);
        m_decoderContent = fmt::format(DECODER_CONTENT_FORMAT, m_decoderName);

        // Integration
        m_integrationName = fmt::format(INTEGRATION_NAME_FORMAT, sessionName);
        m_integrationContent = fmt::format(INTEGRATION_CONTENT_FORMAT, m_decoderName, m_filterName, m_integrationName);

        // Policy
        //m_policyName = fmt::format(POLICY_NAME_FORMAT, sessionName);
        m_policyName = POLICY_NAME_FORMAT;
        m_policyContent = fmt::format(POLICY_CONTENT_FORMAT, m_policyName, m_integrationName);

        // Route
        m_routeName = fmt::format(ROUTE_NAME_FORMAT, sessionName);
        m_routeContent = fmt::format(ROUTE_TABLE_CONTENT_FORMAT, m_routeName, m_filterName, m_policyName);
    }

    void sessionPost(std::shared_ptr<::router::Router> router)
    {
        const auto error = router->addRoute(m_routeName, 55, m_filterName, m_policyName);
        ASSERT_FALSE(error.has_value()) << error.value().message;

        // Suscribe to output and Trace
        // TODO: session.getPolicy()
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            router->subscribeOutputAndTraces(POLICY_NAME_FORMAT);
        }
    }

    void sessionPut(std::shared_ptr<::router::Router> router)
    {
        router->removeRoute(m_routeName);
        router->stop();
    }

    const std::string& getRouteName(){return m_routeName;}
    const std::string& getFilterName(){return m_filterName;}
    const std::string& getPolicyName(){return m_policyName;}
    const std::string& getIntegrationName(){return m_integrationName;}
    const std::string& getDecoderName(){return m_decoderName;}
    const std::string& getRouteContent(){return m_routeContent;}
    const std::string& getFilterContent(){return m_filterContent;}
    const std::string& getPolicyContent(){return m_policyContent;}
    const std::string& getIntegrationContent(){return m_integrationContent;}
    const std::string& getDecoderContent(){return m_decoderContent;}

private:

    std::mutex m_mutex;

    std::string m_filterName;
    std::string m_policyName;
    std::string m_integrationName;
    std::string m_decoderName;
    std::string m_routeName;
    std::string m_filterContent;
    std::string m_policyContent;
    std::string m_integrationContent;
    std::string m_decoderContent;
    std::string m_routeContent;
};

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

class TestRunWithoutFilesCommand : public ::testing::TestWithParam<std::tuple<std::string, std::string>>
{
protected:
    Config m_testConfig;
    api::Handler m_cmdAPI;
    std::shared_ptr<::router::Router> m_spRouter;
    std::shared_ptr<MockStore> m_spMockStore;
    std::shared_ptr<FakeSession> m_spSession;
    std::shared_ptr<builder::Builder> m_spBuilder;

    void SetUp() override
    {
        initLogging();

        m_spMockStore = std::make_shared<MockStore>();
        m_spBuilder = fakeBuilder(m_spMockStore);

        m_spSession = std::make_shared<FakeSession>("policy/test_env_A1/0");

        EXPECT_CALL(*m_spMockStore, get(testing::_))
        .WillRepeatedly(testing::Invoke(
            [&](const base::Name& name)
            {
                if (name == ROUTE_TABLE_NAME)
                {
                    return json::Json {m_spSession->getRouteContent().c_str()};
                }
                else if (name == m_spSession->getFilterName())
                {
                    return json::Json {m_spSession->getFilterContent().c_str()};
                }
                else
                {
                    // Handle other cases or return a default value
                    return json::Json {};
                }
            }));

        m_spRouter = std::make_shared<::router::Router>(m_spBuilder, m_spMockStore);

        auto eventQueue = std::make_shared<base::queue::ConcurrentQueue<base::Event>>(
                100, std::make_shared<FakeMetricScope>(), std::make_shared<FakeMetricScope>());
        m_spRouter->run(eventQueue);
    }
};

TEST_P(TestRunWithoutFilesCommand, ParameterEvaluation)
{
    auto [input, output] = GetParam();

    EXPECT_CALL(*m_spMockStore, get(testing::_))
        .WillRepeatedly(testing::Invoke(
            [&](const base::Name& name)
            {
                if (name == m_spSession->getFilterName())
                {
                    return json::Json {m_spSession->getFilterContent().c_str()};
                }
                else if (name == m_spSession->getIntegrationName())
                {
                    return json::Json {m_spSession->getIntegrationContent().c_str()};
                }
                else if (name == m_spSession->getPolicyName())
                {
                    return json::Json {m_spSession->getPolicyContent().c_str()};
                }
                else if (name == m_spSession->getDecoderName())
                {
                    return json::Json {m_spSession->getDecoderContent().c_str()};
                }
                else
                {
                    // Handle other cases or return a default value
                    return json::Json {};
                }
            }));

    EXPECT_CALL(*m_spMockStore, update(testing::_, testing::_)).WillOnce(testing::Return(std::nullopt));

    m_spSession->sessionPost(m_spRouter);
    m_testConfig = {m_spRouter};

    ASSERT_NO_THROW(m_cmdAPI = resourceRun(m_testConfig));
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
    
    EXPECT_CALL(*m_spMockStore, update(testing::_, testing::_)).WillOnce(testing::Return(std::nullopt));
    m_spSession->sessionPut(m_spRouter);
}

INSTANTIATE_TEST_SUITE_P(
    ParameterEvaluation,
    TestRunWithoutFilesCommand,
    ::testing::Values(
        std::make_tuple(R"({})", R"({"status":"ERROR","error":"Missing /session name"})"),
        std::make_tuple(R"({"session":"policy/test_env_A1/0", "event":"hello world!"})", R"({
            "status": "OK",
            "output": {
                "wazuh": {
                    "message": "hello world!",
                    "location": "/dev/stdin",
                    "queue": 49
                }
            }
        })"),
        std::make_tuple(R"({"session":"policy/test_env_A1/0", "event":"hello world!", "debugmode":1})", R"({
            "status": "OK",
            "output": {
                "wazuh": {
                    "message": "hello world!",
                    "location": "/dev/stdin",
                    "queue": 49
                }
            },
            "traces": {
                "decoder": {
                    "test-policy": {
                        "test_env_A1": [
                            [
                                "failure"
                            ]
                        ]
                    }
                }
            }
        })")));
