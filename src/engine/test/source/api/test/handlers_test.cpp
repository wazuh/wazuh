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
constexpr auto ASSET_PATH {"test/source/api/test/assets/"};
constexpr auto ROUTER_TABLE {"internal/router_table/0"};
constexpr auto JSON_DECODER {"decoder/core-hostinfo/0"};
constexpr auto JSON_FILTER {"filter/allow-all/0"};
constexpr auto JSON_POLICY {"policy/env_A1/0"};
constexpr auto JSON_INTEGRATION {"integration/wazuh_core_test/0"};

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

base::Expression coutOutputHelper_test(const std::string& targetField,
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

std::shared_ptr<builder::Builder> getFakeBuilder(std::shared_ptr<MockStore> store)
{
    auto registry = std::make_shared<builder::internals::Registry<builder::internals::Builder>>();
    auto helperRegistry = std::make_shared<builder::internals::Registry<builder::internals::HelperBuilder>>();
    builder::internals::dependencies dependencies;
    dependencies.helperRegistry = helperRegistry;
    dependencies.logparDebugLvl = 0;
    dependencies.schema = schemf::mocks::EmptySchema::create();
    builder::internals::registerHelperBuilders(helperRegistry);
    builder::internals::registerBuilders(registry, dependencies);

    helperRegistry->registerBuilder(coutOutputHelper_test, "coutOutputHelper_test");

    auto builder = std::make_shared<builder::Builder>(store, registry);

    return builder;
};

class TestRunCommand : public ::testing::TestWithParam<std::tuple<std::string, std::string>>
{
protected:
    Config m_testConfig;
    api::Handler m_cmdAPI;
    std::shared_ptr<::router::Router> m_spRouter;
    std::tuple<std::string, std::string, std::string, std::string> m_paths;
    std::shared_ptr<MockStore> m_spMockStore;

    void SetUp() override
    {
        initLogging();

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

        m_paths = std::make_tuple(pathFilter, pathIntegration, pathPolicy, pathDecoder);

        m_spMockStore = std::make_shared<MockStore>();
        auto builder = getFakeBuilder(m_spMockStore);

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

        m_spRouter = std::make_shared<::router::Router>(builder, m_spMockStore);
        auto eventQueue = std::make_shared<base::queue::ConcurrentQueue<base::Event>>(
                100, std::make_shared<FakeMetricScope>(), std::make_shared<FakeMetricScope>());
        m_spRouter->run(eventQueue);

        m_testConfig = {m_spRouter};
    }
};

TEST_P(TestRunCommand, ParameterEvaluation)
{
    auto [input, output] = GetParam();

    EXPECT_CALL(*m_spMockStore, get(testing::_))
        .WillRepeatedly(testing::Invoke(
            [&](const base::Name& name)
            {
                if (name == JSON_FILTER)
                {
                    return json::Json {readJsonFile(std::get<0>(m_paths)).c_str()};
                }
                else if (name == JSON_INTEGRATION)
                {
                    return json::Json {readJsonFile(std::get<1>(m_paths)).c_str()};
                }
                else if (name == JSON_POLICY)
                {
                    return json::Json {readJsonFile(std::get<2>(m_paths)).c_str()};
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

    EXPECT_CALL(*m_spMockStore, update(testing::_, testing::_)).WillOnce(testing::Return(std::nullopt));

    auto error = m_spRouter->addRoute("allow_all_A1", 101, "filter/allow-all/0", "policy/env_A1/0");
    ASSERT_FALSE(error.has_value()) << error.value().message;

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

    m_spRouter->removeRoute("allow_all_A1");

    m_spRouter->stop();
}

INSTANTIATE_TEST_SUITE_P(
    ParameterEvaluation,
    TestRunCommand,
    ::testing::Values(
        std::make_tuple(R"({})", R"({"status":"ERROR","error":"Missing /policy name"})"),
        std::make_tuple(R"({"policy":"policy/env_A1/0", "event":"hello world!"})", R"({
            "status": "OK",
            "output": {
                "wazuh": {
                    "queue": 49,
                    "message": "hello world!",
                    "location": "/dev/stdin"
                }
            },
            "traces": {}
        })"),
        std::make_tuple(R"({"policy":"policy/env_A1/0", "event":"hello world!", "debugmode":1})", R"({
            "status": "OK",
            "output": {
                "wazuh": {
                    "queue": 49,
                    "location": "/dev/stdin",
                    "message": "hello world!"
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
        std::make_tuple(R"({"policy":"policy/env_A1/0", "event":"hello world!", "debugmode":2})", R"({
            "status": "OK",
            "output": {
                "wazuh": {
                    "message": "hello world!",
                    "queue": 49,
                    "location": "/dev/stdin"
                }
            },
            "traces": {
                "decoder": {
                    "core-hostinfo": [
                        "[decoder/core-hostinfo/0] [condition.value[/wazuh/queue==51]] -> Failure[decoder/core-hostinfo/0] [condition]:failure"
                    ]
                }
            }
        })"),
        std::make_tuple(R"({"policy":"policy/env_A1/0", "event":"hello world!", "debugmode":4})", R"({
            "status": "OK",
            "output": {
                "wazuh": {
                    "queue": 49,
                    "message": "hello world!",
                    "location": "/dev/stdin"
                }
            },
            "traces": {}
        })")));
