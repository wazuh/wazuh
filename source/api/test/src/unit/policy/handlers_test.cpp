#include <gtest/gtest.h>

#include <api/policy/handlers.hpp>

#include <policy/mockPolicy.hpp>

using namespace api::policy::mocks;
using namespace api::policy::handlers;

template<typename T>
class PolicyHandlersTest : public ::testing::TestWithParam<T>
{
protected:
    std::shared_ptr<MockPolicy> m_policy;

    void SetUp() override { m_policy = std::make_shared<MockPolicy>(); }

    void TearDown() override { m_policy.reset(); }
};

using ExpectedFn = std::function<api::wpResponse(const std::shared_ptr<MockPolicy>&)>;
using Behaviour = std::function<void(std::shared_ptr<MockPolicy>)>;

const std::string STATUS_PATH = "/status";
const std::string STATUS_OK = "OK";
const std::string STATUS_ERROR = "ERROR";

ExpectedFn success(const Behaviour& behaviour = {}, const std::string& data = {})
{
    return [behaviour, data](const std::shared_ptr<MockPolicy>& policy) -> api::wpResponse
    {
        if (behaviour)
        {
            behaviour(policy);
        }
        json::Json dataR;
        if (!data.empty())
        {
            try
            {
                dataR = json::Json {data.c_str()};
            }
            catch (const std::exception& e)
            {
                std::cerr << "Error parsing data: [" << e.what() << "] " << data << std::endl;
                throw;
            }
        }
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

using GetHandlerToTest = std::function<api::Handler(const std::shared_ptr<api::policy::IPolicy>&)>;
using TestPolT = std::tuple<GetHandlerToTest, std::string, ExpectedFn>;
using PolicyHandlerTest = PolicyHandlersTest<TestPolT>;

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
    testing::Values( // [storePost] Test create policy
                     // fail
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
        // ok
        TestPolT(storePost,
                 R"( { "policy": "policy/name/0" } )",
                 success(
                     [](auto policy) {
                         EXPECT_CALL(*policy, create(base::Name {"policy/name/0"}))
                             .WillOnce(::testing::Return(std::nullopt));
                     })),
        // [storeDelete] Test delete policy
        // fail
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
        // ok
        TestPolT(storeDelete,
                 R"( { "policy": "policy/name/0" } )",
                 success(
                     [](auto policy) {
                         EXPECT_CALL(*policy, del(base::Name {"policy/name/0"}))
                             .WillOnce(::testing::Return(std::nullopt));
                     })),
        // [storeGet] Test get policy
        // fail
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
        // ok
        TestPolT(storeGet,
                 R"( { "policy": "policy/name/0" } )",
                 success(
                     [](auto policy)
                     {
                         EXPECT_CALL(*policy, get(base::Name {"policy/name/0"}, std::vector<store::NamespaceId> {}))
                             .WillOnce(::testing::Return("Dump of policy"));
                     },
                     R"({ "data": "Dump of policy" })")),
        TestPolT(storeGet,
                 R"( { "policy": "policy/name/0", "namespaces" : ["user"]} )",
                 success(
                     [](auto policy)
                     {
                         EXPECT_CALL(*policy, get(base::Name {"policy/name/0"}, std::vector<store::NamespaceId> {"user"}))
                             .WillOnce(::testing::Return("Dump of policy"));
                     },
                     R"({ "data": "Dump of policy" })")),
        TestPolT(storeGet,
                 R"( { "policy": "policy/name/0", "namespaces" : ["user", "wazuh"]} )",
                 success(
                     [](auto policy)
                     {
                         EXPECT_CALL(*policy, get(base::Name {"policy/name/0"}, std::vector<store::NamespaceId> {"user", "wazuh"}))
                             .WillOnce(::testing::Return("Dump of policy"));
                     },
                     R"({ "data": "Dump of policy" })")),
        // [policyAssetPost] post an asset to a policy
        // fail
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
        // OK
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
        // [policyAssetDelete] Delete an asset to a policy
        // fail
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
        // OK
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
        // [policyAssetGet] Get a list of assets from a policy
        // fail
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
        TestPolT(policyAssetGet,
                 R"( { "policy": "policy/valid/0", "namespace" : "nsName" } )",
                 failure()),
        TestPolT(policyAssetGet,
                 R"( { "policy": "policy/name/0", "namespace" : "nsName" } )",
                 failure(
                     [](auto policy)
                     {
                         EXPECT_CALL(*policy, listAssets(base::Name {"policy/name/0"}, store::NamespaceId {"nsName"}))
                             .WillOnce(::testing::Return(base::Error {}));
                     })),
        // ok
        TestPolT(policyAssetGet,
                 R"( { "policy": "policy/name/0", "namespace" : "nsName" } )",
                 success(
                     [](auto policy)
                     {
                         EXPECT_CALL(*policy, listAssets(base::Name {"policy/name/0"}, store::NamespaceId {"nsName"}))
                             .WillOnce(::testing::Return(std::list<base::Name> {"asseet/name/0", "asseet/name/1"}));
                     },
                     R"({ "data":["asseet/name/0","asseet/name/1"] })"))

        // End
        ));
