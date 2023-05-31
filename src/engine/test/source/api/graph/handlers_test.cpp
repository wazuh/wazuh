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
    std::tuple<std::string, std::string, std::string, std::string, std::string> paths;

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
        auto pathLogpar = absolutePath / JSON_SCHEMA;
        auto pathPolicy = absolutePath / JSON_POLICY;
        auto pathIntegration = absolutePath / JSON_INTEGRATION;
        auto pathDecoder = absolutePath / JSON_DECODER;
        auto pathFilter = absolutePath / JSON_FILTER;

        paths = std::make_tuple(pathLogpar, pathPolicy, pathIntegration, pathDecoder, pathFilter);

        m_spMockStore = std::make_shared<MockStore>();
        auto metrics = std::make_shared<metricsManager::MetricsManager>();
        kvdbManager::KVDBManagerOptions kvdbOptions { cmd::ENGINE_KVDB2_PATH, "kvdb" };
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
                        return json::Json {readJsonFile(std::get<0>(paths)).c_str()};
                    }
                    else if (name == JSON_POLICY)
                    {
                        return json::Json {readJsonFile(std::get<1>(paths)).c_str()};
                    }
                    else if (name == JSON_INTEGRATION)
                    {
                        return json::Json {readJsonFile(std::get<2>(paths)).c_str()};
                    }
                    else if (name == JSON_DECODER)
                    {
                        return json::Json {readJsonFile(std::get<3>(paths)).c_str()};
                    }
                    else if (name == JSON_FILTER)
                    {
                        return json::Json {readJsonFile(std::get<4>(paths)).c_str()};
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
        "content":"strict digraph G {\n\n    compound=true;\n    fontname=\"Helvetica,Arial,sans-serif\";\n    fontsize=12;\n    node [color=\"#57abff\", fontname=\"Helvetica,Arial,sans-serif\", fontsize=10, fontcolor=\"white\"];\n    edge [fontname=\"Helvetica,Arial,sans-serif\", fontsize=8];\n    \nsubgraph cluster_16 {\n\n    style=\"rounded,filled\";\n    color=\"#57abff\";\n    \nlabel=\"Chain\";\n16 [label=\"policy/wazuh/0 [16]\"];\n}\n16 -> 17 [ltail=cluster_16 lhead=cluster_17 label=0 fontcolor=\"red\"];\nsubgraph cluster_17 {\n\n    style=\"rounded,filled\";\n    color=\"#57abff\";\n    \nlabel=\"Or\";\n17 [label=\"decodersInput [17]\"];\n}\n17 -> 18 [ltail=cluster_17 lhead=cluster_18 label=0 fontcolor=\"red\"];\nsubgraph cluster_18 {\n\n    style=\"rounded,filled\";\n    color=\"#57abff\";\n    \nlabel=\"Implication\";\n18 [label=\"decoder/core-hostinfo/0 [18]\"];\n}\n18 -> 9 [ltail=cluster_18 lhead=cluster_9 label=0 fontcolor=\"red\"];\nsubgraph cluster_9 {\n\n    style=\"rounded,filled\";\n    color=\"#57abff\";\n    \nlabel=\"And\";\n9 [label=\"stage.check [9]\"];\n}\n9 -> 8 [ltail=cluster_9 lhead=cluster_8 label=0 fontcolor=\"red\"];\nsubgraph cluster_8 {\n\n    style=\"rounded,filled\";\n    color=\"#57abff\";\n    \nlabel=\"Term\";\n8 [label=\"condition.value[/wazuh/queue==51] [8]\"];\n}\n18 -> 10 [ltail=cluster_18 lhead=cluster_10 label=1 fontcolor=\"red\"];\nsubgraph cluster_10 {\n\n    style=\"rounded,filled\";\n    color=\"#57abff\";\n    \nlabel=\"And\";\n10 [label=\"stages [10]\"];\n}\n10 -> 14 [ltail=cluster_10 lhead=cluster_14 label=0 fontcolor=\"red\"];\nsubgraph cluster_14 {\n\n    style=\"rounded,filled\";\n    color=\"#57abff\";\n    \nlabel=\"Chain\";\n14 [label=\"stage.normalize [14]\"];\n}\n14 -> 13 [ltail=cluster_14 lhead=cluster_13 label=0 fontcolor=\"red\"];\nsubgraph cluster_13 {\n\n    style=\"rounded,filled\";\n    color=\"#57abff\";\n    \nlabel=\"And\";\n13 [label=\"subblock [13]\"];\n}\n13 -> 12 [ltail=cluster_13 lhead=cluster_12 label=0 fontcolor=\"red\"];\nsubgraph cluster_12 {\n\n    style=\"rounded,filled\";\n    color=\"#57abff\";\n    \nlabel=\"Chain\";\n12 [label=\"stage.map [12]\"];\n}\n12 -> 11 [ltail=cluster_12 lhead=cluster_11 label=0 fontcolor=\"red\"];\nsubgraph cluster_11 {\n\n    style=\"rounded,filled\";\n    color=\"#57abff\";\n    \nlabel=\"Term\";\n11 [label=\"helper.array_append[/wazuh/decoders, core-hostinfo] [11]\"];\n}\n}\n"}
        )")));
