#include <api/catalog/catalog.hpp>
#include <api/graph/handlers.hpp>
#include <cmds/src/defaultSettings.hpp>
#include <metrics/metricsManager.hpp>
#include <mocks/store.hpp>
#include <unistd.h>

#include <filesystem>
#include <fstream>

#include <gtest/gtest.h>

#include <testsCommon.hpp>

using namespace api::graph::handlers;

const std::string rCommand {"dummy cmd"};
const std::string rOrigin {"Dummy org module"};
constexpr auto ASSET_PATH {"test/source/api/graph/assets/"};
constexpr auto BUFFER_PATH_SIZE {1024};
constexpr auto JSON_DECODER {"decoder/core-hostinfo/0"};
constexpr auto JSON_FILTER {"filter/allow-all/0"};
constexpr auto JSON_INTEGRATION {"integration/wazuh-core/0"};
constexpr auto JSON_POLICY {"policy/wazuh/0"};
constexpr auto JSON_SCHEMA {"schema/wazuh-logpar-types/0"};
const auto PATH_POLICY = GRAPH_ASSETS_PATH_TEST + std::string(JSON_POLICY);
const auto PATH_DECODER = GRAPH_ASSETS_PATH_TEST + std::string(JSON_DECODER);
const auto PATH_FILTER = GRAPH_ASSETS_PATH_TEST + std::string(JSON_FILTER);
const auto PATH_INTEGRATION = GRAPH_ASSETS_PATH_TEST + std::string(JSON_INTEGRATION);
const auto PATH_SCHEMA = GRAPH_ASSETS_PATH_TEST + std::string(JSON_SCHEMA);

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

class GraphGetCommand : public ::testing::TestWithParam<std::tuple<std::string, std::string>>
{
protected:
    api::graph::handlers::Config graphConfig;
    api::Handler cmdAPI;
    std::shared_ptr<MockStore> m_spMockStore;

    void SetUp() override
    {
        initLogging();

        std::filesystem::path currentPath = std::filesystem::current_path();

        m_spMockStore = std::make_shared<MockStore>();
        auto metrics = std::make_shared<metricsManager::MetricsManager>();
        kvdbManager::KVDBManagerOptions kvdbOptions { cmd::ENGINE_KVDB_PATH, "kvdb" };
        auto kvdb = std::make_shared<kvdbManager::KVDBManager>(kvdbOptions, metrics);
        graphConfig = {m_spMockStore, kvdb};
    }
};

TEST_P(GraphGetCommand, ParameterEvaluation)
{
    auto [input, output] = GetParam();

    EXPECT_CALL(*m_spMockStore, get(testing::_))
            .WillRepeatedly(testing::Invoke(
                [&](const base::Name& name)
                {
                    if (name == JSON_SCHEMA)
                    {
                        return json::Json {readJsonFile(PATH_SCHEMA).c_str()};
                    }
                    else if (name == JSON_POLICY)
                    {
                        return json::Json {readJsonFile(PATH_POLICY).c_str()};
                    }
                    else if (name == JSON_INTEGRATION)
                    {
                        return json::Json {readJsonFile(PATH_INTEGRATION).c_str()};
                    }
                    else if (name == JSON_DECODER)
                    {
                        return json::Json {readJsonFile(PATH_DECODER).c_str()};
                    }
                    else if (name == JSON_FILTER)
                    {
                        return json::Json {readJsonFile(PATH_FILTER).c_str()};
                    }
                    else
                    {
                        // Handle other cases or return a default value
                        return json::Json {};
                    }
                }));

    ASSERT_NO_THROW(cmdAPI = resourceGet(graphConfig));
    json::Json params {input.c_str()};
    base::utils::wazuhProtocol::WazuhRequest request;
    ASSERT_NO_THROW(request = api::wpRequest::create(rCommand, rOrigin, params));
    auto response = cmdAPI(request);

    // check response
    const auto expectedData = json::Json {output.c_str()};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                             << "Expected: " << expectedData.prettyStr() << std::endl;
}

INSTANTIATE_TEST_SUITE_P(
    ParameterEvaluation,
    GraphGetCommand,
    ::testing::Values(
        std::make_tuple(R"({})", R"({"status":"ERROR","error":"Missing or invalid /policy parameter"})"),
        std::make_tuple(
            R"({"policy": "policy/pepe/0", "type": "policy"})",
            R"({"status":"ERROR","error":"An error occurred while building the policy: Policy /name is not defined"})"),
        std::make_tuple(
            R"({"policy": "policy/wazuh/0", "type": "pepe"})",
            R"({"status":"ERROR","error":"Invalid /type parameter, must be either 'policy' or 'expressions'"})"),
        std::make_tuple(R"({"policy": "policy/wazuh/0"})",
                        R"({"status":"ERROR","error":"Missing or invalid /type parameter"})"),
        std::make_tuple(R"({"type": "policy"})",
                        R"({"status":"ERROR","error":"Missing or invalid /policy parameter"})"),
        std::make_tuple(R"({"policy":"policy/wazuh/0","type": "policy"})", R"({"status":"OK",
        "content":"digraph G {\ncompound=true;\nfontname=\"Helvetica,Arial,sans-serif\";\nfontsize=12;\nnode [fontname=\"Helvetica,Arial,sans-serif\", fontsize=10];\nedge [fontname=\"Helvetica,Arial,sans-serif\", fontsize=8];\nenvironment [label=\"policy/wazuh/0\", shape=Mdiamond];\n\nsubgraph cluster_decoders {\nlabel=\"decoders\";\nstyle=filled;\ncolor=lightgrey;\nnode [style=filled,color=white];\ndecodercorehostinfo0 [label=\"decoder/core-hostinfo/0\"];\ndecodersInput [label=\"decodersInput\"];\ndecodersInput -> decodercorehostinfo0;\n}\nenvironment -> decodersInput;\n}\n"}
        )"),
        std::make_tuple(R"({"policy":"policy/wazuh/0","type": "expressions"})", R"({"status":"OK",
        "content": "strict digraph G {\n\n    compound=true;\n    fontname=\"Helvetica,Arial,sans-serif\";\n    fontsize=12;\n    node [color=\"#57abff\", fontname=\"Helvetica,Arial,sans-serif\", fontsize=10, fontcolor=\"white\"];\n    edge [fontname=\"Helvetica,Arial,sans-serif\", fontsize=8];\n    \nsubgraph cluster_8 {\n\n    style=\"rounded,filled\";\n    color=\"#57abff\";\n    \nlabel=\"Chain\";\n8 [label=\"policy/wazuh/0 [8]\"];\n}\n8 -> 9 [ltail=cluster_8 lhead=cluster_9 label=0 fontcolor=\"red\"];\nsubgraph cluster_9 {\n\n    style=\"rounded,filled\";\n    color=\"#57abff\";\n    \nlabel=\"Or\";\n9 [label=\"decodersInput [9]\"];\n}\n9 -> 10 [ltail=cluster_9 lhead=cluster_10 label=0 fontcolor=\"red\"];\nsubgraph cluster_10 {\n\n    style=\"rounded,filled\";\n    color=\"#57abff\";\n    \nlabel=\"Implication\";\n10 [label=\"decoder/core-hostinfo/0 [10]\"];\n}\n10 -> 1 [ltail=cluster_10 lhead=cluster_1 label=0 fontcolor=\"red\"];\nsubgraph cluster_1 {\n\n    style=\"rounded,filled\";\n    color=\"#57abff\";\n    \nlabel=\"And\";\n1 [label=\"stage.check [1]\"];\n}\n1 -> 0 [ltail=cluster_1 lhead=cluster_0 label=0 fontcolor=\"red\"];\nsubgraph cluster_0 {\n\n    style=\"rounded,filled\";\n    color=\"#57abff\";\n    \nlabel=\"Term\";\n0 [label=\"condition.value[/wazuh/queue==51] [0]\"];\n}\n10 -> 2 [ltail=cluster_10 lhead=cluster_2 label=1 fontcolor=\"red\"];\nsubgraph cluster_2 {\n\n    style=\"rounded,filled\";\n    color=\"#57abff\";\n    \nlabel=\"And\";\n2 [label=\"stages [2]\"];\n}\n2 -> 6 [ltail=cluster_2 lhead=cluster_6 label=0 fontcolor=\"red\"];\nsubgraph cluster_6 {\n\n    style=\"rounded,filled\";\n    color=\"#57abff\";\n    \nlabel=\"Chain\";\n6 [label=\"stage.normalize [6]\"];\n}\n6 -> 5 [ltail=cluster_6 lhead=cluster_5 label=0 fontcolor=\"red\"];\nsubgraph cluster_5 {\n\n    style=\"rounded,filled\";\n    color=\"#57abff\";\n    \nlabel=\"And\";\n5 [label=\"subblock [5]\"];\n}\n5 -> 4 [ltail=cluster_5 lhead=cluster_4 label=0 fontcolor=\"red\"];\nsubgraph cluster_4 {\n\n    style=\"rounded,filled\";\n    color=\"#57abff\";\n    \nlabel=\"Chain\";\n4 [label=\"stage.map [4]\"];\n}\n4 -> 3 [ltail=cluster_4 lhead=cluster_3 label=0 fontcolor=\"red\"];\nsubgraph cluster_3 {\n\n    style=\"rounded,filled\";\n    color=\"#57abff\";\n    \nlabel=\"Term\";\n3 [label=\"helper.array_append[/wazuh/decoders, core-hostinfo] [3]\"];\n}\n}\n"}
        )")));
