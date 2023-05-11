#include <api/graph/handlers.hpp>
#include <cmds/src/defaultSettings.hpp>
#include <metrics/metricsManager.hpp>
#include <unistd.h>

#include <filesystem>
#include <fstream>

#include <gtest/gtest.h>
#include <testsCommon.hpp>

using namespace api::graph::handlers;

const std::string rCommand {"dummy cmd"};
const std::string rOrigin {"Dummy org module"};

class GraphGetCommand : public ::testing::Test
{
protected:
    Config graphConfig;
    api::Handler cmdAPI;
    std::shared_ptr<store::FileDriver> store;

    void SetUp() override
    {
        initLogging();

        char buffer[1024];
        if (getcwd(buffer, sizeof(buffer)) != NULL)
        {
            std::string path(buffer);
            size_t pos = path.find_last_of('/');
            if (pos != std::string::npos) {
                path = path.substr(0, pos);
                path += "/test/source/api/graph/assets/";
                store = std::make_shared<store::FileDriver>(path);
            }
        }

        auto metrics = std::make_shared<metricsManager::MetricsManager>();
        auto kvdb = std::make_shared<kvdb_manager::KVDBManager>(cmd::ENGINE_KVDB_PATH, metrics);
        graphConfig = {store, kvdb};
    }
};

TEST_F(GraphGetCommand, ParametersNotFound)
{
    ASSERT_NO_THROW(cmdAPI = resourceGet(graphConfig));
    json::Json params {R"({})"};
    base::utils::wazuhProtocol::WazuhRequest request;
    ASSERT_NO_THROW(request = api::wpRequest::create(rCommand, rOrigin, params));
    auto response = cmdAPI(request);

    // check response
    const auto expectedData = json::Json {R"({"status":"ERROR","error":"Missing or invalid /policy parameter"})"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                             << "Expected: " << expectedData.prettyStr() << std::endl;
}

TEST_F(GraphGetCommand, ParametersPolicyNotFound)
{
    ASSERT_NO_THROW(cmdAPI = resourceGet(graphConfig));
    json::Json params {R"({"policy": "policy/pepe/0", "type": "policy"})"};
    base::utils::wazuhProtocol::WazuhRequest request;
    ASSERT_NO_THROW(request = api::wpRequest::create(rCommand, rOrigin, params));
    auto response = cmdAPI(request);

    // check response
    const auto expectedData = json::Json {R"({"status":"ERROR","error":"An error occurred while building the policy: Engine builder: Policy 'policy/pepe/0' could not be obtained from the store: File '/home/vagrant/engine/wazuh/src/engine/test/source/api/graph/assets/policy/pepe/0' does not exist."})"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                             << "Expected: " << expectedData.prettyStr() << std::endl;
}

TEST_F(GraphGetCommand, ParametersTypeNotFound)
{
    ASSERT_NO_THROW(cmdAPI = resourceGet(graphConfig));
    json::Json params {R"({"policy": "policy/wazuh/0", "type": "pepe"})"};
    base::utils::wazuhProtocol::WazuhRequest request;
    ASSERT_NO_THROW(request = api::wpRequest::create(rCommand, rOrigin, params));
    auto response = cmdAPI(request);

    // check response
    const auto expectedData = json::Json {R"({"status":"ERROR","error":"Invalid /type parameter, must be either 'policy' or 'expressions'"})"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                             << "Expected: " << expectedData.prettyStr() << std::endl;
}

TEST_F(GraphGetCommand, ParametersTypeMissing)
{
    ASSERT_NO_THROW(cmdAPI = resourceGet(graphConfig));
    json::Json params {R"({"policy": "policy/wazuh/0"})"};
    base::utils::wazuhProtocol::WazuhRequest request;
    ASSERT_NO_THROW(request = api::wpRequest::create(rCommand, rOrigin, params));
    auto response = cmdAPI(request);

    // check response
    const auto expectedData = json::Json {R"({"status":"ERROR","error":"Missing or invalid /type parameter"})"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                             << "Expected: " << expectedData.prettyStr() << std::endl;
}

TEST_F(GraphGetCommand, ParametersPolicyMissing)
{
    ASSERT_NO_THROW(cmdAPI = resourceGet(graphConfig));
    json::Json params {R"({"type": "policy"})"};
    base::utils::wazuhProtocol::WazuhRequest request;
    ASSERT_NO_THROW(request = api::wpRequest::create(rCommand, rOrigin, params));
    auto response = cmdAPI(request);

    // check response
    const auto expectedData = json::Json {R"({"status":"ERROR","error":"Missing or invalid /policy parameter"})"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                             << "Expected: " << expectedData.prettyStr() << std::endl;
}

TEST_F(GraphGetCommand, ValidParametersTypePolicy)
{
    ASSERT_NO_THROW(cmdAPI = resourceGet(graphConfig));
    json::Json params {R"({"policy":"policy/wazuh/0","type": "policy"})"};
    base::utils::wazuhProtocol::WazuhRequest request;
    ASSERT_NO_THROW(request = api::wpRequest::create(rCommand, rOrigin, params));
    auto response = cmdAPI(request);

    // check response
    const auto expectedData = json::Json {R"({"status":"OK",
        "content":"digraph G {\ncompound=true;\nfontname=\"Helvetica,Arial,sans-serif\";\nfontsize=12;\nnode [fontname=\"Helvetica,Arial,sans-serif\", fontsize=10];\nedge [fontname=\"Helvetica,Arial,sans-serif\", fontsize=8];\nenvironment [label=\"policy/wazuh/0\", shape=Mdiamond];\n\nsubgraph cluster_decoders {\nlabel=\"decoders\";\nstyle=filled;\ncolor=lightgrey;\nnode [style=filled,color=white];\ndecodercorehostinfo0 [label=\"decoder/core-hostinfo/0\"];\ndecodersInput [label=\"decodersInput\"];\ndecodersInput -> decodercorehostinfo0;\n}\nenvironment -> decodersInput;\n}\n"}
        )"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                             << "Expected: " << expectedData.prettyStr() << std::endl;
}

TEST_F(GraphGetCommand, ValidParametersTypeExpressions)
{
    ASSERT_NO_THROW(cmdAPI = resourceGet(graphConfig));
    json::Json params {R"({"policy":"policy/wazuh/0","type": "expressions"})"};
    base::utils::wazuhProtocol::WazuhRequest request;
    ASSERT_NO_THROW(request = api::wpRequest::create(rCommand, rOrigin, params));
    auto response = cmdAPI(request);

    // check response
    const auto expectedData = json::Json {R"({"status":"OK",
        "content":"strict digraph G {\n\n    compound=true;\n    fontname=\"Helvetica,Arial,sans-serif\";\n    fontsize=12;\n    node [color=\"#57abff\", fontname=\"Helvetica,Arial,sans-serif\", fontsize=10, fontcolor=\"white\"];\n    edge [fontname=\"Helvetica,Arial,sans-serif\", fontsize=8];\n    \nsubgraph cluster_16 {\n\n    style=\"rounded,filled\";\n    color=\"#57abff\";\n    \nlabel=\"Chain\";\n16 [label=\"policy/wazuh/0 [16]\"];\n}\n16 -> 17 [ltail=cluster_16 lhead=cluster_17 label=0 fontcolor=\"red\"];\nsubgraph cluster_17 {\n\n    style=\"rounded,filled\";\n    color=\"#57abff\";\n    \nlabel=\"Or\";\n17 [label=\"decodersInput [17]\"];\n}\n17 -> 18 [ltail=cluster_17 lhead=cluster_18 label=0 fontcolor=\"red\"];\nsubgraph cluster_18 {\n\n    style=\"rounded,filled\";\n    color=\"#57abff\";\n    \nlabel=\"Implication\";\n18 [label=\"decoder/core-hostinfo/0 [18]\"];\n}\n18 -> 9 [ltail=cluster_18 lhead=cluster_9 label=0 fontcolor=\"red\"];\nsubgraph cluster_9 {\n\n    style=\"rounded,filled\";\n    color=\"#57abff\";\n    \nlabel=\"And\";\n9 [label=\"stage.check [9]\"];\n}\n9 -> 8 [ltail=cluster_9 lhead=cluster_8 label=0 fontcolor=\"red\"];\nsubgraph cluster_8 {\n\n    style=\"rounded,filled\";\n    color=\"#57abff\";\n    \nlabel=\"Term\";\n8 [label=\"condition.value[/wazuh/queue==51] [8]\"];\n}\n18 -> 10 [ltail=cluster_18 lhead=cluster_10 label=1 fontcolor=\"red\"];\nsubgraph cluster_10 {\n\n    style=\"rounded,filled\";\n    color=\"#57abff\";\n    \nlabel=\"And\";\n10 [label=\"stages [10]\"];\n}\n10 -> 14 [ltail=cluster_10 lhead=cluster_14 label=0 fontcolor=\"red\"];\nsubgraph cluster_14 {\n\n    style=\"rounded,filled\";\n    color=\"#57abff\";\n    \nlabel=\"Chain\";\n14 [label=\"stage.normalize [14]\"];\n}\n14 -> 13 [ltail=cluster_14 lhead=cluster_13 label=0 fontcolor=\"red\"];\nsubgraph cluster_13 {\n\n    style=\"rounded,filled\";\n    color=\"#57abff\";\n    \nlabel=\"And\";\n13 [label=\"subblock [13]\"];\n}\n13 -> 12 [ltail=cluster_13 lhead=cluster_12 label=0 fontcolor=\"red\"];\nsubgraph cluster_12 {\n\n    style=\"rounded,filled\";\n    color=\"#57abff\";\n    \nlabel=\"Chain\";\n12 [label=\"stage.map [12]\"];\n}\n12 -> 11 [ltail=cluster_12 lhead=cluster_11 label=0 fontcolor=\"red\"];\nsubgraph cluster_11 {\n\n    style=\"rounded,filled\";\n    color=\"#57abff\";\n    \nlabel=\"Term\";\n11 [label=\"helper.array_append[/wazuh/decoders, core-hostinfo] [11]\"];\n}\n}\n"}
        )"};

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Response: " << response.data().prettyStr() << std::endl
                                             << "Expected: " << expectedData.prettyStr() << std::endl;
}
