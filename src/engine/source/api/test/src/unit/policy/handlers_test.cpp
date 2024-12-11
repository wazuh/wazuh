/**
 * @file handlers_test.cpp
 * @brief Unit tests for policy handlers.
 *
 * This file contains unit tests for the policy handlers, which are responsible for processing policy-related requests.
 * The tests cover various scenarios, including successful and failed requests, and different combinations of
 * parameters. The tests use a mock policy object to simulate policy data and behavior.
 *
 */
#include <gtest/gtest.h>

#include <api/policy/handlers.hpp>

#include <api/policy/mockPolicy.hpp>

using namespace api::policy::mocks;
using namespace api::policy::handlers;

/***
 * @brief Represent the type signature of the all function to test
 *
 * The handlers is created with a function that return the handler to test.
 */
using GetHandlerToTest = std::function<api::HandlerSync(const std::shared_ptr<api::policy::IPolicy>&)>;

/**
 * @brief Represent the type signature of the expected function
 *
 * The expected function return the response of the handler.
 */
using ExpectedFn = std::function<api::wpResponse(const std::shared_ptr<MockPolicy>&)>;

/**
 * @brief Test parameters.
 * @param getHandlerFn Function that return the handler to test.
 * @param params Parameters to pass to the handler.
 * @param expectedFn Function that return the expected response.
 */
using TestPolT = std::tuple<GetHandlerToTest, json::Json, ExpectedFn>;

/**
 * @brief Describe the behaviour of the handler (mocks function)
 *
 * Its used for build a success or fail response
 */
using Behaviour = std::function<void(std::shared_ptr<MockPolicy>)>;

/**
 * @brief Describe the behaviour of the handler (mocks function) with return
 * json::Json is the return type
 *
 * Its used for build a success or fail response
 */
using BehaviourWRet = std::function<json::Json(std::shared_ptr<MockPolicy>)>;

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

/**
 * @brief User for build the params of the handler in a easy way
 *
 */
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

/**
 * @brief User for build the response of the handler in a easy way
 *
 */
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

class PolicyHandlerTest : public ::testing::TestWithParam<TestPolT>
{
protected:
    std::shared_ptr<MockPolicy> m_policy;

    void SetUp() override { m_policy = std::make_shared<MockPolicy>(); }

    void TearDown() override { m_policy.reset(); }
};

TEST_P(PolicyHandlerTest, processRequest)
{
    const auto [getHandlerFn, params, expectedFn] = GetParam();

    auto expectedResponse = expectedFn(m_policy);
    auto request = api::wpRequest::create("policy.command", "test", params);

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
        TestPolT(storePost, JParams("test"), failure()),
        TestPolT(storePost, JParams(""), failure()),
        TestPolT(storePost, JParams("other/name/version"), failure()),
        TestPolT(storePost, JParams("pol/name/version"), failure()),
        TestPolT(storePost, JParams("policy/name/version/ext"), failure()),
        TestPolT(storePost, JParams("policy/name"), failure()),
        TestPolT(storePost, JParams("policy/"), failure()),
        TestPolT(storePost, JParams("policy//0"), failure()),
        TestPolT(storePost,
                 JParams(POLICY_NAME),
                 failure(
                     [](auto policy) {
                         EXPECT_CALL(*policy, create(base::Name {POLICY_NAME}))
                             .WillOnce(::testing::Return(base::Error {}));
                     })),
        // [storePost]: OK
        TestPolT(
            storePost,
            JParams(POLICY_NAME),
            success(
                [](auto policy)
                { EXPECT_CALL(*policy, create(base::Name {POLICY_NAME})).WillOnce(::testing::Return(std::nullopt)); })),
        // [storeDelete]: fail
        TestPolT(storeDelete, JParams("test"), failure()),
        TestPolT(storeDelete, JParams(""), failure()),
        TestPolT(storeDelete, JParams("other/name/version"), failure()),
        TestPolT(storeDelete, JParams("pol/name/version"), failure()),
        TestPolT(storeDelete, JParams("policy/name/version/ext"), failure()),
        TestPolT(storeDelete, JParams("policy/name"), failure()),
        TestPolT(storeDelete, JParams("policy/"), failure()),
        TestPolT(storeDelete, JParams("policy//0"), failure()),
        TestPolT(
            storeDelete,
            JParams(POLICY_NAME),
            failure(
                [](auto policy)
                { EXPECT_CALL(*policy, del(base::Name {POLICY_NAME})).WillOnce(::testing::Return(base::Error {})); })),
        // [storeDelete]: ok
        TestPolT(storeDelete,
                 JParams(POLICY_NAME),
                 success(
                     [](auto policy) {
                         EXPECT_CALL(*policy, del(base::Name {POLICY_NAME})).WillOnce(::testing::Return(std::nullopt));
                     })),
        // [storeGet]: fail
        TestPolT(storeGet, R"( { "name": "test" } )", failure()),
        TestPolT(storeGet, JParams(""), failure()),
        TestPolT(storeGet, JParams("other/name/version"), failure()),
        TestPolT(storeGet, JParams("pol/name/version"), failure()),
        TestPolT(storeGet, JParams("policy/name/version/ext"), failure()),
        TestPolT(storeGet, JParams("policy/name"), failure()),
        TestPolT(storeGet, JParams("policy/"), failure()),
        TestPolT(storeGet, JParams("policy//0"), failure()),
        TestPolT(storeGet, JParams(POLICY_NAME).namespaces("invalid/name"), failure()),
        TestPolT(storeGet, JParams(POLICY_NAME).namespaces({NAMESPACE_U, ""}), failure()),
        TestPolT(storeGet, JParams(POLICY_NAME).namespaces({"", NAMESPACE_U}), failure()),
        TestPolT(storeGet, JParams(POLICY_NAME).namespaces({NAMESPACE_W, NAMESPACE_U}), failure()),
        TestPolT(storeGet,
                 JParams(POLICY_NAME),
                 failure(
                     [](auto policy)
                     {
                         EXPECT_CALL(*policy, get(base::Name {POLICY_NAME}, std::vector<store::NamespaceId> {}))
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
                         return JPayload().setString("Dump of policy", "/data");
                     })),

        TestPolT(storeGet,
                 JParams(POLICY_NAME).namespaces(NAMESPACE_U),
                 successWPayload(
                     [](auto policy)
                     {
                         EXPECT_CALL(*policy,
                                     get(base::Name {POLICY_NAME}, std::vector<store::NamespaceId> {NAMESPACE_U}))
                             .WillOnce(::testing::Return("Dump of policy"));
                         return JPayload().setString("Dump of policy", "/data");
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
        TestPolT(policyAssetPost, JParams(""), failure()),
        TestPolT(policyAssetPost, JParams("other/name/version").asset(ASSET_NAME_A), failure()),
        TestPolT(policyAssetPost, JParams("pol/name/version").asset(ASSET_NAME_A), failure()),
        TestPolT(policyAssetPost, JParams("policy/name/version/ext").asset(ASSET_NAME_A), failure()),
        TestPolT(policyAssetPost, JParams("policy/name").asset(ASSET_NAME_A), failure()),
        TestPolT(policyAssetPost, JParams("policy/").asset(ASSET_NAME_A), failure()),
        TestPolT(policyAssetPost, JParams(POLICY_NAME).asset(ASSET_NAME_A), failure()),
        TestPolT(policyAssetPost, JParams(POLICY_NAME).namespace_("invalid/name").asset(ASSET_NAME_A), failure()),
        TestPolT(policyAssetPost, JParams(POLICY_NAME).namespace_(NAMESPACE_U).asset(""), failure()),
        TestPolT(policyAssetPost, JParams(POLICY_NAME).namespace_(NAMESPACE_U).asset("/"), failure()),
        TestPolT(policyAssetPost, JParams(POLICY_NAME).namespace_(NAMESPACE_U).asset("as/"), failure()),

        TestPolT(policyAssetPost, JParams(POLICY_NAME).namespace_(NAMESPACE_U).asset("/asd"), failure()),
        TestPolT(policyAssetPost, JParams(POLICY_NAME).namespace_(NAMESPACE_U).asset("invalid/name"), failure()),
        TestPolT(policyAssetPost, JParams(POLICY_NAME).namespace_(NAMESPACE_U).asset("invalid/name/exc/va"), failure()),
        TestPolT(policyAssetPost,
                 JParams(POLICY_NAME).namespace_(NAMESPACE_U).asset(ASSET_NAME_A),
                 failure(
                     [](auto policy)
                     {
                         EXPECT_CALL(*policy,
                                     addAsset(base::Name {POLICY_NAME},
                                              store::NamespaceId {NAMESPACE_U},
                                              base::Name {ASSET_NAME_A}))
                             .WillOnce(::testing::Return(base::Error {}));
                     })),
        // [policyAssetPost]: Ok
        TestPolT(policyAssetPost,
                 JParams(POLICY_NAME).namespace_(NAMESPACE_U).asset(ASSET_NAME_A),
                 successWPayload(
                     [](auto policy)
                     {
                         EXPECT_CALL(*policy,
                                     addAsset(base::Name {POLICY_NAME},
                                              store::NamespaceId {NAMESPACE_U},
                                              base::Name {ASSET_NAME_A}))
                             .WillOnce(::testing::Return(std::string()));

                         return JPayload().setString("", "/warning");
                     })),
        // [policyAssetDelete]: Fail
        TestPolT(policyAssetDelete, JParams(""), failure()),
        TestPolT(policyAssetDelete, JParams("other/name/version").asset(ASSET_NAME_A), failure()),
        TestPolT(policyAssetDelete, JParams("pol/name/version").asset(ASSET_NAME_A), failure()),
        TestPolT(policyAssetDelete, JParams("policy/name/version/ext").asset(ASSET_NAME_A), failure()),
        TestPolT(policyAssetDelete, JParams("policy/name").asset(ASSET_NAME_A), failure()),
        TestPolT(policyAssetDelete, JParams("policy/").asset(ASSET_NAME_A), failure()),
        TestPolT(policyAssetDelete, JParams(POLICY_NAME).asset(ASSET_NAME_A), failure()),
        TestPolT(policyAssetDelete, JParams(POLICY_NAME).namespace_("invalid/name").asset(ASSET_NAME_A), failure()),
        TestPolT(policyAssetDelete, JParams(POLICY_NAME).namespace_(NAMESPACE_U).asset(""), failure()),
        TestPolT(policyAssetDelete, JParams(POLICY_NAME).namespace_(NAMESPACE_U).asset("/"), failure()),
        TestPolT(policyAssetDelete, JParams(POLICY_NAME).namespace_(NAMESPACE_U).asset("as/"), failure()),

        TestPolT(policyAssetDelete, JParams(POLICY_NAME).namespace_(NAMESPACE_U).asset("/asd"), failure()),
        TestPolT(policyAssetDelete, JParams(POLICY_NAME).namespace_(NAMESPACE_U).asset("invalid/name"), failure()),
        TestPolT(policyAssetDelete,
                 JParams(POLICY_NAME).namespace_(NAMESPACE_U).asset("invalid/name/exc/va"),
                 failure()),
        TestPolT(policyAssetDelete,
                 JParams(POLICY_NAME).namespace_(NAMESPACE_U).asset(ASSET_NAME_A),
                 failure(
                     [](auto policy)
                     {
                         EXPECT_CALL(*policy,
                                     delAsset(base::Name {POLICY_NAME},
                                              store::NamespaceId {NAMESPACE_U},
                                              base::Name {ASSET_NAME_A}))
                             .WillOnce(::testing::Return(base::Error {}));
                     })),
        // [policyAssetDelete]: Ok
        TestPolT(policyAssetDelete,
                 JParams(POLICY_NAME).namespace_(NAMESPACE_U).asset(ASSET_NAME_A),
                 successWPayload(
                     [](auto policy)
                     {
                         EXPECT_CALL(*policy,
                                     delAsset(base::Name {POLICY_NAME},
                                              store::NamespaceId {NAMESPACE_U},
                                              base::Name {ASSET_NAME_A}))
                             .WillOnce(::testing::Return(std::string()));

                         return JPayload().setString("", "/warning");
                     })),
        // [policyAssetGet]: Fail
        TestPolT(policyAssetGet, R"( { "name": "test" } )", failure()),
        TestPolT(policyAssetGet, JParams(""), failure()),
        TestPolT(policyAssetGet, JParams("other/name/version"), failure()),
        TestPolT(policyAssetGet, JParams("pol/name/version"), failure()),
        TestPolT(policyAssetGet, JParams("policy/name/version/ext"), failure()),
        TestPolT(policyAssetGet, JParams("policy/name"), failure()),
        TestPolT(policyAssetGet, JParams("policy/"), failure()),
        TestPolT(policyAssetGet, JParams("policy//0"), failure()),
        TestPolT(policyAssetGet, JParams(POLICY_NAME).namespace_("invalid/name"), failure()),
        TestPolT(policyAssetGet, JParams(POLICY_NAME).namespace_(""), failure()),
        TestPolT(policyAssetGet,
                 JParams(POLICY_NAME).namespace_(NAMESPACE_U),
                 failure(
                     [](auto policy)
                     {
                         EXPECT_CALL(*policy, listAssets(base::Name {POLICY_NAME}, store::NamespaceId {NAMESPACE_U}))
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
                         EXPECT_CALL(*policy,
                                     getDefaultParent(base::Name {POLICY_NAME}, store::NamespaceId {NAMESPACE_U}))
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
                             .WillOnce(::testing::Return(std::list<base::Name> {ASSET_NAME_A}));
                         return JPayload().setArray("/data").appendString(ASSET_NAME_A, "/data");
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
                 successWPayload(
                     [](auto policy)
                     {
                         EXPECT_CALL(*policy,
                                     setDefaultParent(base::Name {POLICY_NAME},
                                                      store::NamespaceId {NAMESPACE_U},
                                                      base::Name {ASSET_NAME_A}))
                             .WillOnce(::testing::Return(std::string()));

                         return JPayload().setString("", "/warning");
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
                 JParams(POLICY_NAME).namespace_(NAMESPACE_U).parent(ASSET_NAME_A),
                 failure(
                     [](auto policy)
                     {
                         EXPECT_CALL(
                             *policy,
                             delDefaultParent(base::Name {POLICY_NAME}, store::NamespaceId {NAMESPACE_U}, testing::_))
                             .WillOnce(::testing::Return(base::Error {}));
                     })),
        // [policyDefaultParentDelete]: ok
        TestPolT(policyDefaultParentDelete,
                 JParams(POLICY_NAME).namespace_(NAMESPACE_U).parent(ASSET_NAME_B),
                 successWPayload(
                     [](auto policy)
                     {
                         EXPECT_CALL(
                             *policy,
                             delDefaultParent(base::Name {POLICY_NAME}, store::NamespaceId {NAMESPACE_U}, testing::_))
                             .WillOnce(::testing::Return(std::string()));

                         return JPayload().setString("", "/warning");
                     })),
        // [policiesGet]: Fail
        TestPolT(policiesGet,
                 R"( { } )",
                 failure([](auto policy) { EXPECT_CALL(*policy, list()).WillOnce(::testing::Return(base::Error {})); }

                         )),
        // [policiesGet]: ok
        TestPolT(policiesGet,
                 R"( { } )",
                 successWPayload(
                     [](auto policy)
                     {
                         EXPECT_CALL(*policy, list())
                             .WillOnce(::testing::Return(std::vector<base::Name> {POLICY_NAME}));
                         return JPayload().setArray("/data").appendString(POLICY_NAME, "/data");
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
        TestPolT(policyNamespacesGet,
                 JParams(POLICY_NAME),
                 failure(
                     [](auto policy) {
                         EXPECT_CALL(*policy, listNamespaces(base::Name {POLICY_NAME}))
                             .WillOnce(::testing::Return(base::Error {}));
                     })),
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
