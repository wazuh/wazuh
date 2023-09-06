#include <gtest/gtest.h>

#include <api/policy/handlers.hpp>

#include <api/policy/mockPolicy.hpp>

using namespace api::policy::mocks;
using namespace api::policy::handlers;

using ExpectedFn = std::function<api::wpResponse(const std::shared_ptr<MockPolicy>&)>;
using GetHandlerToTest = std::function<api::Handler(const std::shared_ptr<api::policy::IPolicy>&)>;
using TestPolT = std::tuple<GetHandlerToTest, std::string, ExpectedFn>;

using Behaviour = std::function<void(std::shared_ptr<MockPolicy>)>;
using BehaviourWRet = std::function<json::Json(std::shared_ptr<MockPolicy>)>;

class PolicyHandlerTest : public ::testing::TestWithParam<TestPolT>
{
protected:
    std::shared_ptr<MockPolicy> m_policy;

    void SetUp() override { m_policy = std::make_shared<MockPolicy>(); }

    void TearDown() override { m_policy.reset(); }
};


const std::string STATUS_PATH = "/status";
const std::string STATUS_OK = "OK";
const std::string STATUS_ERROR = "ERROR";


ExpectedFn success(const Behaviour& behaviour = {})
{
    return [behaviour](const std::shared_ptr<MockPolicy>& policy) -> api::wpResponse
    {
        if (behaviour)
        {
            behaviour(policy);
        }
        json::Json dataR;
        dataR.setString(STATUS_OK, STATUS_PATH);
        return api::wpResponse {dataR};
    };
}

ExpectedFn successWPayload(const BehaviourWRet& behaviour)
{
    if (!behaviour)
    {
        throw std::runtime_error("Behaviour with return must be defined");
    }
    return [behaviour](const std::shared_ptr<MockPolicy>& policy) -> api::wpResponse
    {
        json::Json dataR = behaviour(policy);
        dataR.setString(STATUS_OK, STATUS_PATH);
        return api::wpResponse {dataR};
    };
}

ExpectedFn failure(const Behaviour& behaviour = {})
{
    return [behaviour](const std::shared_ptr<MockPolicy>& policy) -> api::wpResponse
    {
        if (behaviour)
        {
            behaviour(policy);
        }
        json::Json failStatus;
        failStatus.setString(STATUS_ERROR, STATUS_PATH);
        return api::wpResponse(failStatus);
    };
}

// Valid params
const std::string POLICY_NAME = "policy/name/0";
const std::string NAMESPACE_U = "user";
const std::string NAMESPACE_W = "wazuh";
const std::string NAMESPACE_S = "system";
const std::string ASSET_NAME_A = "asset/name/0";
const std::string ASSET_NAME_B = "asset/name/1";

struct JParams
{

    std::optional<std::string> m_policy;
    std::optional<std::string> m_namespace;
    std::optional<std::string> m_asset;
    std::optional<std::vector<std::string>> m_namespaces;
    std::optional<std::string> m_parent;

    JParams(const std::string& policy)
        : m_policy(policy)
    {
    }

    JParams& namespace_(const std::string& ns)
    {
        m_namespace = ns;
        return *this;
    }

    JParams& asset(const std::string& asset)
    {
        m_asset = asset;
        return *this;
    }

    JParams& namespaces(const std::vector<std::string>& namespaces)
    {

        m_namespaces = namespaces;
        return *this;
    }

    JParams& namespaces(const std::string& namespaces)
    {

        if (m_namespaces)
        {
            m_namespaces.value().push_back(namespaces);
        }
        else
        {
            m_namespaces = std::vector<std::string> {namespaces};
        }

        return *this;
    }

    JParams& parent(const std::string& parent)
    {
        m_parent = parent;
        return *this;
    }

    // cast to json
    operator json::Json() const
    {
        json::Json j;
        if (m_policy)
        {
            j.setString(m_policy.value(), "/policy");
        }
        if (m_namespace)
        {
            j.setString(m_namespace.value(), "/namespace");
        }
        if (m_asset)
        {
            j.setString(m_asset.value(), "/asset");
        }
        if (m_namespaces)
        {
            j.setArray("/namespaces");
            for (const auto& ns : m_namespaces.value())
            {
                j.appendString(ns, "/namespaces");
            }
        }
        if (m_parent)
        {
            j.setString(m_parent.value(), "/parent");
        }
        return j;
    }

    // cast to string
    operator std::string() const { return json::Json(*this).str(); }
};

struct JPayload
{
    json::Json m_json;

    JPayload() = default;
    // All function of json::Json are available
    JPayload& setString(const std::string& value, const std::string& path)
    {
        m_json.setString(value, path);
        return *this;
    }

    JPayload& setArray(const std::string& path)
    {
        m_json.setArray(path);
        return *this;
    }

    JPayload& appendString(const std::string& value, const std::string& path)
    {
        m_json.appendString(value, path);
        return *this;
    }

    // cast to json
    operator json::Json() const { return m_json; }

    operator std::string() const { return m_json.str(); }
};



TEST_P(PolicyHandlerTest, processRequest)
{
    const auto [getHandlerFn, params, expectedFn] = GetParam();

    json::Json jParams;
    try
    {
        jParams = json::Json {params.c_str()};
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error parsing params: [" << e.what() << "] " << params << std::endl;
        throw;
    }

    auto expectedResponse = expectedFn(m_policy);
    auto request = api::wpRequest::create("policy.command", "test", jParams);

    auto response = getHandlerFn(m_policy)(request);

    if (expectedResponse.data().getString(STATUS_PATH) == STATUS_ERROR)
    {
        auto status = expectedResponse.data().getString(STATUS_PATH);
        ASSERT_TRUE(status.has_value()) << "Expected status code";
        ASSERT_EQ(status.value(), STATUS_ERROR) << "Expected ERROR status code";
    }
    else
    {
        ASSERT_EQ(expectedResponse.data(), response.data());
    }
}

INSTANTIATE_TEST_SUITE_P(
    HandlerPolicyTest,
    PolicyHandlerTest,
    testing::Values(
        // [storePost]: Fail
        TestPolT(storePost, R"( { "name": "test" } )", failure()),
        TestPolT(storePost, R"( { "policy": "" } )", failure()),
        TestPolT(storePost, R"( { "policy": "other/name/version" } )", failure()),
        TestPolT(storePost, R"( { "policy": "pol/name/version" } )", failure()),
        TestPolT(storePost, R"( { "policy": "policy/name/version/ext" } )", failure()),
        TestPolT(storePost, R"( { "policy": "policy/name" } )", failure()),
        TestPolT(storePost, R"( { "policy": "policy/" } )", failure()),
        TestPolT(storePost, R"( { "policy": "policy//0" } )", failure()),
        TestPolT(storePost,
                 R"( { "policy": "policy/name/0" } )",
                 failure(
                     [](auto policy) {
                         EXPECT_CALL(*policy, create(base::Name {"policy/name/0"}))
                             .WillOnce(::testing::Return(base::Error {}));
                     })),
        // [storePost]: OK
        TestPolT(storePost,
                 R"( { "policy": "policy/name/0" } )",
                 success(
                     [](auto policy) {
                         EXPECT_CALL(*policy, create(base::Name {"policy/name/0"}))
                             .WillOnce(::testing::Return(std::nullopt));
                     })),
        // [storeDelete]: fail
        TestPolT(storeDelete, R"( { "name": "test" } )", failure()),
        TestPolT(storeDelete, R"( { "policy": "" } )", failure()),
        TestPolT(storeDelete, R"( { "policy": "other/name/version" } )", failure()),
        TestPolT(storeDelete, R"( { "policy": "pol/name/version" } )", failure()),
        TestPolT(storeDelete, R"( { "policy": "policy/name/version/ext" } )", failure()),
        TestPolT(storeDelete, R"( { "policy": "policy/name" } )", failure()),
        TestPolT(storeDelete, R"( { "policy": "policy/" } )", failure()),
        TestPolT(storeDelete, R"( { "policy": "policy//0" } )", failure()),
        TestPolT(storeDelete,
                 R"( { "policy": "policy/name/0" } )",
                 failure(
                     [](auto policy) {
                         EXPECT_CALL(*policy, del(base::Name {"policy/name/0"}))
                             .WillOnce(::testing::Return(base::Error {}));
                     })),
        // [storeDelete]: ok
        TestPolT(storeDelete,
                 R"( { "policy": "policy/name/0" } )",
                 success(
                     [](auto policy) {
                         EXPECT_CALL(*policy, del(base::Name {"policy/name/0"}))
                             .WillOnce(::testing::Return(std::nullopt));
                     })),
        // [storeGet]: fail
        TestPolT(storeGet, R"( { "name": "test" } )", failure()),
        TestPolT(storeGet, R"( { "policy": "" } )", failure()),
        TestPolT(storeGet, R"( { "policy": "other/name/version" } )", failure()),
        TestPolT(storeGet, R"( { "policy": "pol/name/version" } )", failure()),
        TestPolT(storeGet, R"( { "policy": "policy/name/version/ext" } )", failure()),
        TestPolT(storeGet, R"( { "policy": "policy/name" } )", failure()),
        TestPolT(storeGet, R"( { "policy": "policy/" } )", failure()),
        TestPolT(storeGet, R"( { "policy": "policy//0" } )", failure()),
        TestPolT(storeGet, R"( { "policy": "policy/valid/0", "namespaces" : ["invalid/name"] } )", failure()),
        TestPolT(storeGet, R"( { "policy": "policy/valid/0", "namespaces" : ["validName" , ""] } )", failure()),
        TestPolT(storeGet, R"( { "policy": "policy/valid/0", "namespaces" : ["", "validName"] } )", failure()),
        TestPolT(storeGet,
                 R"( { "policy": "policy/valid/0", "namespaces" : ["validName", "invalid/name"] } )",
                 failure()),
        TestPolT(storeGet,
                 R"( { "policy": "policy/name/0" } )",
                 failure(
                     [](auto policy)
                     {
                         EXPECT_CALL(*policy, get(base::Name {"policy/name/0"}, std::vector<store::NamespaceId> {}))
                             .WillOnce(::testing::Return(base::Error {}));
                     })),
        // [storeGet]: ok
        TestPolT(storeGet,
                 JParams(POLICY_NAME),
                 successWPayload(
                     [](auto policy) -> json::Json
                     {
                         JParams params(POLICY_NAME);
                         EXPECT_CALL(*policy,
                                     get(base::Name {params.m_policy.value()}, std::vector<store::NamespaceId> {}))
                             .WillOnce(::testing::Return("Dump of policy"));
                         return json::Json {R"({"data": "Dump of policy"})"};
                     })),

        TestPolT(storeGet,
                 JParams(POLICY_NAME).namespaces(NAMESPACE_U),
                 successWPayload(
                     [](auto policy)
                     {
                         EXPECT_CALL(*policy,
                                     get(base::Name {POLICY_NAME}, std::vector<store::NamespaceId> {NAMESPACE_U}))
                             .WillOnce(::testing::Return("Dump of policy"));
                         return json::Json {R"({"data": "Dump of policy"})"};
                     })),
        TestPolT(storeGet,
                 JParams(POLICY_NAME).namespaces(NAMESPACE_U).namespaces(NAMESPACE_W),
                 successWPayload(
                     [](auto policy)
                     {
                         EXPECT_CALL(
                             *policy,
                             get(base::Name {POLICY_NAME}, std::vector<store::NamespaceId> {NAMESPACE_U, NAMESPACE_W}))
                             .WillOnce(::testing::Return("Dump of policy"));
                         return json::Json {R"({"data": "Dump of policy"})"};
                     })),

        // [policyAssetPost]: Fail
        TestPolT(policyAssetPost, R"( { "policy": "" } )", failure()),
        TestPolT(policyAssetPost, R"( { "policy": "other/name/version", "asset": "valid/asset/name"  } )", failure()),
        TestPolT(policyAssetPost, R"( { "policy": "pol/name/version", "asset": "valid/asset/name"  } )", failure()),
        TestPolT(policyAssetPost,
                 R"( { "policy": "policy/name/version/ext", "asset": "valid/asset/name"  } )",
                 failure()),
        TestPolT(policyAssetPost, R"( { "policy": "policy/name", "asset": "valid/asset/name"  } )", failure()),
        TestPolT(policyAssetPost, R"( { "policy": "policy/", "asset": "valid/asset/name"  } )", failure()),
        TestPolT(policyAssetPost, R"( { "policy": "policy/valid/0", "asset": "valid/asset/name"  } )", failure()),
        TestPolT(policyAssetPost,
                 R"( { "policy": "policy/valid/0", "namespaces" : ["invalid/name"], "asset": "valid/asset/name"  } )",
                 failure()),
        TestPolT(policyAssetPost,
                 R"( { "policy": "policy/valid/0", "namespaces" : ["validName" , ""], "asset": "valid/asset/name"  } )",
                 failure()),
        TestPolT(policyAssetPost,
                 R"( { "policy": "policy/valid/0", "namespaces" : ["", "validName"], "asset": "valid/asset/name"  } )",
                 failure()),
        TestPolT(
            policyAssetPost,
            R"( { "policy": "policy/valid/0", "namespaces" : ["validName", "invalid/name"], "asset": "valid/asset/name"  } )",
            failure()),
        TestPolT(policyAssetPost,
                 R"( { "policy": "policy/name/0", "namespace": "user", "asset":  "valid/asset/name" } )",
                 failure(
                     [](auto policy)
                     {
                         EXPECT_CALL(*policy,
                                     addAsset(base::Name {"policy/name/0"},
                                              store::NamespaceId {"user"},
                                              base::Name {"valid/asset/name"}))
                             .WillOnce(::testing::Return(base::Error {}));
                     })),
        // [policyAssetPost]: Ok
        TestPolT(policyAssetPost,
                 R"( { "policy": "policy/name/0", "namespace": "user", "asset":  "valid/asset/name" } )",
                 success(
                     [](auto policy)
                     {
                         EXPECT_CALL(*policy,
                                     addAsset(base::Name {"policy/name/0"},
                                              store::NamespaceId {"user"},
                                              base::Name {"valid/asset/name"}))
                             .WillOnce(::testing::Return(std::nullopt));
                     })),
        // [policyAssetDelete]: Fail
        TestPolT(policyAssetDelete, R"( { "policy": "" } )", failure()),
        TestPolT(policyAssetDelete, R"( { "policy": "other/name/version", "asset": "valid/asset/name"  } )", failure()),
        TestPolT(policyAssetDelete, R"( { "policy": "pol/name/version", "asset": "valid/asset/name"  } )", failure()),
        TestPolT(policyAssetDelete,
                 R"( { "policy": "policy/name/version/ext", "asset": "valid/asset/name"  } )",
                 failure()),
        TestPolT(policyAssetDelete, R"( { "policy": "policy/name", "asset": "valid/asset/name"  } )", failure()),
        TestPolT(policyAssetDelete, R"( { "policy": "policy/", "asset": "valid/asset/name"  } )", failure()),
        TestPolT(policyAssetDelete, R"( { "policy": "policy/valid/0", "asset": "valid/asset/name"  } )", failure()),
        TestPolT(policyAssetDelete,
                 R"( { "policy": "policy/valid/0", "namespaces" : ["invalid/name"], "asset": "valid/asset/name"  } )",
                 failure()),
        TestPolT(policyAssetDelete,
                 R"( { "policy": "policy/valid/0", "namespaces" : ["validName" , ""], "asset": "valid/asset/name"  } )",
                 failure()),
        TestPolT(policyAssetDelete,
                 R"( { "policy": "policy/valid/0", "namespaces" : ["", "validName"], "asset": "valid/asset/name"  } )",
                 failure()),
        TestPolT(
            policyAssetDelete,
            R"( { "policy": "policy/valid/0", "namespaces" : ["validName", "invalid/name"], "asset": "valid/asset/name"  } )",
            failure()),
        TestPolT(policyAssetDelete,
                 R"( { "policy": "policy/name/0", "namespace": "user", "asset":  "valid/asset/name" } )",
                 failure(
                     [](auto policy)
                     {
                         EXPECT_CALL(*policy,
                                     delAsset(base::Name {"policy/name/0"},
                                              store::NamespaceId {"user"},
                                              base::Name {"valid/asset/name"}))
                             .WillOnce(::testing::Return(base::Error {}));
                     })),
        // [policyAssetDelete]: Ok
        TestPolT(policyAssetDelete,
                 R"( { "policy": "policy/name/0", "namespace": "user", "asset":  "valid/asset/name" } )",
                 success(
                     [](auto policy)
                     {
                         EXPECT_CALL(*policy,
                                     delAsset(base::Name {"policy/name/0"},
                                              store::NamespaceId {"user"},
                                              base::Name {"valid/asset/name"}))
                             .WillOnce(::testing::Return(std::nullopt));
                     })),
        // [policyAssetGet]: Fail
        TestPolT(policyAssetGet, R"( { "name": "test" } )", failure()),
        TestPolT(policyAssetGet, R"( { "policy": "" } )", failure()),
        TestPolT(policyAssetGet, R"( { "policy": "other/name/version" } )", failure()),
        TestPolT(policyAssetGet, R"( { "policy": "pol/name/version" } )", failure()),
        TestPolT(policyAssetGet, R"( { "policy": "policy/name/version/ext" } )", failure()),
        TestPolT(policyAssetGet, R"( { "policy": "policy/name" } )", failure()),
        TestPolT(policyAssetGet, R"( { "policy": "policy/" } )", failure()),
        TestPolT(policyAssetGet, R"( { "policy": "policy//0" } )", failure()),
        TestPolT(policyAssetGet, R"( { "policy": "policy/valid/0", "namespace" : "invalid/name" } )", failure()),
        TestPolT(policyAssetGet, R"( { "policy": "policy/valid/0", "namespace" : ""} )", failure()),
        TestPolT(policyAssetGet, R"( { "policy": "policy/valid/0", "namespace" : "nsName" } )", failure()),
        TestPolT(policyAssetGet,
                 R"( { "policy": "policy/name/0", "namespace" : "nsName" } )",
                 failure(
                     [](auto policy)
                     {
                         EXPECT_CALL(*policy, listAssets(base::Name {"policy/name/0"}, store::NamespaceId {"nsName"}))
                             .WillOnce(::testing::Return(base::Error {}));
                     })),
        // [policyAssetGet]: ok
        TestPolT(policyAssetGet,
                 JParams(POLICY_NAME).namespace_(NAMESPACE_U),
                 successWPayload(
                     [](auto policy)
                     {
                         EXPECT_CALL(*policy, listAssets(base::Name {POLICY_NAME}, store::NamespaceId {NAMESPACE_U}))
                             .WillOnce(::testing::Return(std::list<base::Name> {ASSET_NAME_A, ASSET_NAME_B}));
                         return JPayload()
                             .setArray("/data")
                             .appendString(ASSET_NAME_A, "/data")
                             .appendString(ASSET_NAME_B, "/data");
                     })),

        // [policyDefaultParentGet]: Fail
        TestPolT(policyDefaultParentGet, R"( { "name": "test" } )", failure()),
        TestPolT(policyDefaultParentGet, JParams("").namespace_(NAMESPACE_U), failure()),
        TestPolT(policyDefaultParentGet, JParams("other/name/version").namespace_(NAMESPACE_U), failure()),
        TestPolT(policyDefaultParentGet, JParams("pol/name/version").namespace_(NAMESPACE_U), failure()),
        TestPolT(policyDefaultParentGet, JParams("policy/name/version/ext").namespace_(NAMESPACE_U), failure()),
        TestPolT(policyDefaultParentGet, JParams("policy/name").namespace_(NAMESPACE_U), failure()),
        TestPolT(policyDefaultParentGet, JParams("policy/").namespace_(NAMESPACE_U), failure()),
        TestPolT(policyDefaultParentGet, JParams("policy//0").namespace_(NAMESPACE_U), failure()),
        TestPolT(policyDefaultParentGet, JParams(POLICY_NAME).namespace_(""), failure()),
        TestPolT(policyDefaultParentGet, JParams(POLICY_NAME).namespace_("other/namespace"), failure()),
        TestPolT(policyDefaultParentGet, JParams(POLICY_NAME).namespace_("/"), failure()),
        TestPolT(policyDefaultParentGet,
                 JParams(POLICY_NAME).namespace_(NAMESPACE_U),
                 failure(
                     [](auto policy)
                     {
                         EXPECT_CALL(*policy, getDefaultParent(base::Name {POLICY_NAME}, store::NamespaceId {NAMESPACE_U}))
                             .WillOnce(::testing::Return(base::Error {}));
                     })),
        // [policyDefaultParentGet]: ok
        TestPolT(policyDefaultParentGet,
                 JParams(POLICY_NAME).namespace_(NAMESPACE_U),
                 successWPayload(
                     [](auto policy)
                     {
                         EXPECT_CALL(*policy,
                                     getDefaultParent(base::Name {POLICY_NAME}, store::NamespaceId {NAMESPACE_U}))
                             .WillOnce(::testing::Return(base::Name {ASSET_NAME_A}));
                         return JPayload().setString(ASSET_NAME_A, "/data");
                     })),
        // [policyDefaultParentPost]: Fail
        TestPolT(policyDefaultParentPost, R"( { "name": "test" } )", failure()),
        TestPolT(policyDefaultParentPost, JParams("").namespace_(NAMESPACE_U).parent(ASSET_NAME_A), failure()),
        TestPolT(policyDefaultParentPost,
                 JParams("other/name/version").namespace_(NAMESPACE_U).parent(ASSET_NAME_A),
                 failure()),
        TestPolT(policyDefaultParentPost,
                 JParams("pol/name/version").namespace_(NAMESPACE_U).parent(ASSET_NAME_A),
                 failure()),
        TestPolT(policyDefaultParentPost,
                 JParams("policy/name/version/ext").namespace_(NAMESPACE_U).parent(ASSET_NAME_A),
                 failure()),
        TestPolT(policyDefaultParentPost,
                 JParams("policy/name").namespace_(NAMESPACE_U).parent(ASSET_NAME_A),
                 failure()),
        TestPolT(policyDefaultParentPost, JParams(POLICY_NAME).namespace_("").parent(ASSET_NAME_A), failure()),
        TestPolT(policyDefaultParentPost, JParams(POLICY_NAME).namespace_("/").parent(ASSET_NAME_A), failure()),
        TestPolT(policyDefaultParentPost, JParams(POLICY_NAME).namespace_("as/asd").parent(ASSET_NAME_A), failure()),
        TestPolT(policyDefaultParentPost, JParams(POLICY_NAME).namespace_("/asd/").parent(ASSET_NAME_A), failure()),

        TestPolT(policyDefaultParentPost, JParams("policy/").namespace_(NAMESPACE_U).parent(ASSET_NAME_A), failure()),
        TestPolT(policyDefaultParentPost, JParams("policy//0").namespace_(NAMESPACE_U).parent(ASSET_NAME_A), failure()),
        TestPolT(policyDefaultParentPost, JParams(POLICY_NAME).namespace_("").parent(ASSET_NAME_A), failure()),
        TestPolT(policyDefaultParentPost,
                 JParams(POLICY_NAME).namespace_("other/namespace").parent(ASSET_NAME_A),
                 failure()),
        TestPolT(policyDefaultParentPost, JParams(POLICY_NAME).namespace_("/").parent(ASSET_NAME_A), failure()),
        TestPolT(policyDefaultParentPost, JParams(POLICY_NAME).namespace_(NAMESPACE_U).parent(""), failure()),
        TestPolT(policyDefaultParentPost,
                 JParams(POLICY_NAME).namespace_(NAMESPACE_U).parent("other/asset"),
                 failure()),
        TestPolT(policyDefaultParentPost, JParams(POLICY_NAME).namespace_(NAMESPACE_U).parent("/"), failure()),
        TestPolT(policyDefaultParentPost,
                 JParams(POLICY_NAME).namespace_(NAMESPACE_U).parent(ASSET_NAME_A),
                 failure(
                     [](auto policy)
                     {
                         EXPECT_CALL(*policy,
                                     setDefaultParent(base::Name {POLICY_NAME},
                                                      store::NamespaceId {NAMESPACE_U},
                                                      base::Name {ASSET_NAME_A}))
                             .WillOnce(::testing::Return(base::Error {}));
                     })),
        // [policyDefaultParentPost]: ok
        TestPolT(policyDefaultParentPost,
                 JParams(POLICY_NAME).namespace_(NAMESPACE_U).parent(ASSET_NAME_A),
                 success(
                     [](auto policy)
                     {
                         EXPECT_CALL(*policy,
                                     setDefaultParent(base::Name {POLICY_NAME},
                                                      store::NamespaceId {NAMESPACE_U},
                                                      base::Name {ASSET_NAME_A}))
                             .WillOnce(::testing::Return(std::nullopt));
                     })),
        // [policyDefaultParentDelete]: Fail
        TestPolT(policyDefaultParentDelete, R"( { "name": "test" } )", failure()),
        TestPolT(policyDefaultParentDelete, JParams("").namespace_(NAMESPACE_U), failure()),
        TestPolT(policyDefaultParentDelete, JParams("other/name/version").namespace_(NAMESPACE_U), failure()),
        TestPolT(policyDefaultParentDelete, JParams("pol/name/version").namespace_(NAMESPACE_U), failure()),
        TestPolT(policyDefaultParentDelete, JParams("policy/name/version/ext").namespace_(NAMESPACE_U), failure()),
        TestPolT(policyDefaultParentDelete, JParams("policy/name").namespace_(NAMESPACE_U), failure()),
        TestPolT(policyDefaultParentDelete, JParams("policy/").namespace_(NAMESPACE_U), failure()),
        TestPolT(policyDefaultParentDelete, JParams("policy//0").namespace_(NAMESPACE_U), failure()),
        TestPolT(policyDefaultParentDelete, JParams(POLICY_NAME).namespace_(""), failure()),
        TestPolT(policyDefaultParentDelete, JParams(POLICY_NAME).namespace_("other/namespace"), failure()),
        TestPolT(policyDefaultParentDelete, JParams(POLICY_NAME).namespace_("/"), failure()),
        TestPolT(policyDefaultParentDelete,
                 JParams(POLICY_NAME).namespace_(NAMESPACE_U),
                 failure(
                     [](auto policy)
                     {
                         EXPECT_CALL(*policy,
                                     delDefaultParent(base::Name {POLICY_NAME}, store::NamespaceId {NAMESPACE_U}))
                             .WillOnce(::testing::Return(base::Error {}));
                     })),
        // [policyDefaultParentDelete]: ok
        TestPolT(policyDefaultParentDelete,
                 JParams(POLICY_NAME).namespace_(NAMESPACE_U),
                 success(
                     [](auto policy)
                     {
                         EXPECT_CALL(*policy,
                                     delDefaultParent(base::Name {POLICY_NAME}, store::NamespaceId {NAMESPACE_U}))
                             .WillOnce(::testing::Return(std::nullopt));
                     })),
        // [policiesGet]: Fail
         TestPolT(policiesGet, R"( { } )", failure(
                    [](auto policy)
                     {
                         EXPECT_CALL(*policy, list())
                             .WillOnce(::testing::Return(base::Error {}));
                     }

         )),
        // [policiesGet]: ok
        TestPolT(policiesGet,
                 R"( { } )",
                 successWPayload(
                     [](auto policy)
                     {
                         EXPECT_CALL(*policy, list())
                             .WillOnce(::testing::Return(std::vector<base::Name> {POLICY_NAME}));
                         return JPayload()
                             .setArray("/data")
                             .appendString(POLICY_NAME, "/data");
                     })),
        // [policyNamespacesGet]: Fail
        TestPolT(policyNamespacesGet, R"( { "name": "test" } )", failure()),
        TestPolT(policyNamespacesGet, JParams(""), failure()),
        TestPolT(policyNamespacesGet, JParams("other/name/version"), failure()),
        TestPolT(policyNamespacesGet, JParams("pol/name/version"), failure()),
        TestPolT(policyNamespacesGet, JParams("policy/name/version/ext"), failure()),
        TestPolT(policyNamespacesGet, JParams("policy/name"), failure()),
        TestPolT(policyNamespacesGet, JParams("policy/"), failure()),
        TestPolT(policyNamespacesGet, JParams("policy//0"), failure()),
        TestPolT(policyNamespacesGet, JParams(POLICY_NAME), failure(
            [](auto policy)
            {
                EXPECT_CALL(*policy, listNamespaces(base::Name {POLICY_NAME}))
                    .WillOnce(::testing::Return(base::Error {}));
            }
        )),
        // [policyNamespacesGet]: ok
        TestPolT(policyNamespacesGet,
                 JParams(POLICY_NAME),
                 successWPayload(
                     [](auto policy)
                     {
                         EXPECT_CALL(*policy, listNamespaces(base::Name {POLICY_NAME}))
                             .WillOnce(::testing::Return(std::list<store::NamespaceId> {NAMESPACE_U, NAMESPACE_W}));
                         return JPayload()
                             .setArray("/data")
                             .appendString(NAMESPACE_U, "/data")
                             .appendString(NAMESPACE_W, "/data");
                     }))
        // End
        ));
