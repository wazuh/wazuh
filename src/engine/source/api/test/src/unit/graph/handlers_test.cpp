#include <api/catalog/catalog.hpp>
#include <api/graph/handlers.hpp>
#include <cmds/src/defaultSettings.hpp>
#include <metrics/metricsManager.hpp>
#include <store/mockStore.hpp>
#include <unistd.h>

#include <filesystem>
#include <fstream>

#include <gtest/gtest.h>

#include "fakeAssets.hpp"

using namespace api::graph::handlers;
using namespace graph::assets;
using namespace store::mocks;

const std::string rCommand {"dummy cmd"};
const std::string rOrigin {"Dummy org module"};
constexpr auto BUFFER_PATH_SIZE {1024};
constexpr auto JSON_DECODER {"decoder/core-hostinfo/0"};
constexpr auto JSON_FILTER {"filter/allow-all/0"};
constexpr auto JSON_INTEGRATION {"integration/wazuh-core/0"};
constexpr auto JSON_POLICY {"policy/wazuh/0"};
constexpr auto JSON_SCHEMA {"schema/wazuh-logpar-types/0"};
constexpr auto CONFLICTING_TEST {7};

class GraphGetCommand : public ::testing::TestWithParam<std::tuple<int, std::string, std::string>>
{
protected:
    api::graph::handlers::Config graphConfig;
    api::HandlerSync cmdAPI;
    std::shared_ptr<MockStore> m_spMockStore;

    void SetUp() override
    {
        logging::testInit();

        std::filesystem::path currentPath = std::filesystem::current_path();

        m_spMockStore = std::make_shared<store::mocks::MockStore>();
        auto metrics = std::make_shared<metricsManager::MetricsManager>();
        kvdbManager::KVDBManagerOptions kvdbOptions {cmd::ENGINE_KVDB_PATH, "kvdb"};
        auto kvdb = std::make_shared<kvdbManager::KVDBManager>(kvdbOptions, metrics);
        graphConfig = {m_spMockStore, kvdb};
    }
};

// TODO: The test of execution number 7 is done in a different way due to the generation of indices that change in each
// execution of the test, for this reason they are omitted.
TEST_P(GraphGetCommand, ParameterEvaluation)
{
    auto [execution, input, output] = GetParam();

    EXPECT_CALL(*m_spMockStore, readInternalDoc(testing::Eq(base::Name {JSON_SCHEMA})))
        .WillRepeatedly(::testing::Return(storeReadDocResp(store::Doc {WAZUH_LOGPAR_TYPES})));

    EXPECT_CALL(*m_spMockStore, readDoc(testing::_))
        .WillRepeatedly(testing::Invoke(
            [&](const base::Name& name)
            {
                if (name == JSON_POLICY)
                {
                    return json::Json {POLICY};
                }
                else if (name == JSON_INTEGRATION)
                {
                    return json::Json {INTEGRATION};
                }
                else if (name == JSON_DECODER)
                {
                    return json::Json {DECODER};
                }
                else if (name == JSON_FILTER)
                {
                    return json::Json {FILTER};
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

    const auto expectedData = json::Json {output.c_str()};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    if (CONFLICTING_TEST == execution)
    {
        // TODO: This is a temporary solution because the index changes with each execution, it is not replaced by a
        // known one.
        std::regex pattern("\\d+");
        auto modifyOutput =
            std::regex_replace(response.data().str(), pattern, std::to_string(CONFLICTING_TEST).c_str());
        ASSERT_EQ(json::Json {modifyOutput.c_str()}, expectedData)
            << "Response: " << modifyOutput.c_str() << std::endl
            << "Expected: " << expectedData.prettyStr() << std::endl;
    }
    else
    {
        ASSERT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                                 << "Expected: " << expectedData.prettyStr() << std::endl;
    }
}

INSTANTIATE_TEST_SUITE_P(
    ParameterEvaluation,
    GraphGetCommand,
    ::testing::Values(
        std::make_tuple(1, R"({})", R"({"status":"ERROR","error":"Missing or invalid /policy parameter"})"),
        std::make_tuple(
            2,
            R"({"policy": "policy/pepe/0", "type": "policy"})",
            R"({"status":"ERROR","error":"An error occurred while building the policy: Policy /name is not defined"})"),
        std::make_tuple(
            3,
            R"({"policy": "policy/wazuh/0", "type": "pepe"})",
            R"({"status":"ERROR","error":"Invalid /type parameter, must be either 'policy' or 'expressions'"})"),
        std::make_tuple(4,
                        R"({"policy": "policy/wazuh/0"})",
                        R"({"status":"ERROR","error":"Missing or invalid /type parameter"})"),
        std::make_tuple(5,
                        R"({"type": "policy"})",
                        R"({"status":"ERROR","error":"Missing or invalid /policy parameter"})"),
        std::make_tuple(6, R"({"policy":"policy/wazuh/0","type": "policy"})", R"({"status":"OK",
        "content":"digraph G {\ncompound=true;\nfontname=\"Helvetica,Arial,sans-serif\";\nfontsize=12;\nnode [fontname=\"Helvetica,Arial,sans-serif\", fontsize=10];\nedge [fontname=\"Helvetica,Arial,sans-serif\", fontsize=8];\nenvironment [label=\"policy/wazuh/0\", shape=Mdiamond];\n\nsubgraph cluster_decoders {\nlabel=\"decoders\";\nstyle=filled;\ncolor=lightgrey;\nnode [style=filled,color=white];\ndecodercorehostinfo0 [label=\"decoder/core-hostinfo/0\"];\ndecodersInput [label=\"decodersInput\"];\ndecodersInput -> decodercorehostinfo0;\n}\nenvironment -> decodersInput;\n}\n"}
        )"),
        std::make_tuple(7, R"({"policy":"policy/wazuh/0","type": "expressions"})", R"({"status":"OK",
        "content":"strict digraph G {\n\n    compound=true;\n    fontname=\"Helvetica,Arial,sans-serif\";\n    fontsize=7;\n    node [color=\"#7abff\", fontname=\"Helvetica,Arial,sans-serif\", fontsize=7, fontcolor=\"white\"];\n    edge [fontname=\"Helvetica,Arial,sans-serif\", fontsize=7];\n    \nsubgraph cluster_7 {\n\n    style=\"rounded,filled\";\n    color=\"#7abff\";\n    \nlabel=\"Chain\";\n7 [label=\"policy/wazuh/7 [7]\"];\n}\n7 -> 7 [ltail=cluster_7 lhead=cluster_7 label=7 fontcolor=\"red\"];\nsubgraph cluster_7 {\n\n    style=\"rounded,filled\";\n    color=\"#7abff\";\n    \nlabel=\"Or\";\n7 [label=\"decodersInput [7]\"];\n}\n7 -> 7 [ltail=cluster_7 lhead=cluster_7 label=7 fontcolor=\"red\"];\nsubgraph cluster_7 {\n\n    style=\"rounded,filled\";\n    color=\"#7abff\";\n    \nlabel=\"Implication\";\n7 [label=\"decoder/core-hostinfo/7 [7]\"];\n}\n7 -> 7 [ltail=cluster_7 lhead=cluster_7 label=7 fontcolor=\"red\"];\nsubgraph cluster_7 {\n\n    style=\"rounded,filled\";\n    color=\"#7abff\";\n    \nlabel=\"And\";\n7 [label=\"stage.check [7]\"];\n}\n7 -> 7 [ltail=cluster_7 lhead=cluster_7 label=7 fontcolor=\"red\"];\nsubgraph cluster_7 {\n\n    style=\"rounded,filled\";\n    color=\"#7abff\";\n    \nlabel=\"Term\";\n7 [label=\"condition.value[/wazuh/queue==7] [7]\"];\n}\n7 -> 7 [ltail=cluster_7 lhead=cluster_7 label=7 fontcolor=\"red\"];\nsubgraph cluster_7 {\n\n    style=\"rounded,filled\";\n    color=\"#7abff\";\n    \nlabel=\"Chain\";\n7 [label=\"stages [7]\"];\n}\n7 -> 7 [ltail=cluster_7 lhead=cluster_7 label=7 fontcolor=\"red\"];\nsubgraph cluster_7 {\n\n    style=\"rounded,filled\";\n    color=\"#7abff\";\n    \nlabel=\"Chain\";\n7 [label=\"stage.normalize [7]\"];\n}\n7 -> 7 [ltail=cluster_7 lhead=cluster_7 label=7 fontcolor=\"red\"];\nsubgraph cluster_7 {\n\n    style=\"rounded,filled\";\n    color=\"#7abff\";\n    \nlabel=\"And\";\n7 [label=\"subblock [7]\"];\n}\n7 -> 7 [ltail=cluster_7 lhead=cluster_7 label=7 fontcolor=\"red\"];\nsubgraph cluster_7 {\n\n    style=\"rounded,filled\";\n    color=\"#7abff\";\n    \nlabel=\"Chain\";\n7 [label=\"stage.map [7]\"];\n}\n7 -> 7 [ltail=cluster_7 lhead=cluster_7 label=7 fontcolor=\"red\"];\nsubgraph cluster_7 {\n\n    style=\"rounded,filled\";\n    color=\"#7abff\";\n    \nlabel=\"Term\";\n7 [label=\"helper.array_append[/wazuh/decoders, core-hostinfo] [7]\"];\n}\n7 -> 7 [ltail=cluster_7 lhead=cluster_7 label=7 fontcolor=\"red\"];\nsubgraph cluster_7 {\n\n    style=\"rounded,filled\";\n    color=\"#7abff\";\n    \nlabel=\"Term\";\n7 [label=\"DeleteVariables [7]\"];\n}\n}\n"}
        )")));
