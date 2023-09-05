#include <gtest/gtest.h>

#include <api/policy/handlers.hpp>

#include <policy/mockPolicy.hpp>

using namespace api::policy::mocks;
using namespace api::policy::handlers;

template <typename T>
class PolicyHandlersTest : public ::testing::TestWithParam<T>
{
protected:
    std::shared_ptr<MockPolicy> m_policy;

    void SetUp() override
    {
        m_policy = std::make_shared<MockPolicy>();
    }

    void TearDown() override
    {
        m_policy.reset();
    }
};

using ExpectedFn = std::function<api::wpResponse(const std::shared_ptr<MockPolicy>&)>;
using Behaviour = std::function<void(std::shared_ptr<MockPolicy>)>;

const std::string STATUS_PATH = "/status";
const std::string STATUS_OK = "OK";
const std::string STATUS_ERROR = "ERROR";

ExpectedFn success(const Behaviour& behaviour = {}, const std::string& data = {})
{
    return [behaviour, data](const std::shared_ptr<MockPolicy>& policy) -> api::wpResponse {
        if (behaviour)
        {
            behaviour(policy);
        }
        json::Json dataR;
        if (!data.empty())
        {
            try {
                dataR = json::Json {data.c_str()};
            } catch (const std::exception& e) {
                std::cerr << "Error parsing data: " << e.what() << std::endl;
                throw;
            }
        }
        dataR.setString(STATUS_OK, STATUS_PATH);
        return api::wpResponse {dataR};
    };
}

ExpectedFn failure(const Behaviour& behaviour = {})
{
    return [behaviour](const std::shared_ptr<MockPolicy>& policy) -> api::wpResponse {
        if (behaviour)
        {
            behaviour(policy);
        }
        json::Json failStatus;
        failStatus.setString(STATUS_ERROR, STATUS_PATH);
        return api::wpResponse(failStatus);
    };
}

/*******************************************************************************
 * [storePost] Test create policy
 ******************************************************************************/
using StorePostT = std::tuple<json::Json, ExpectedFn>;
using StorePostHandler = PolicyHandlersTest<StorePostT>;

TEST_P(StorePostHandler, createPolicy)
{
    const auto [params, expectedFn] = GetParam();

    auto expectedResponse = expectedFn(m_policy);
    auto request = api::wpRequest::create("policy.store/post", "test" , params);

    auto response = storePost(m_policy)(request);

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

INSTANTIATE_TEST_SUITE_P(HandlerPolicyTest,
                         StorePostHandler,
                         testing::Values(StorePostT(json::Json {R"( { "name": "test" } )"}, failure()),
                                         StorePostT(json::Json {R"( { "policy": "" } )"}, failure()),
                                         StorePostT(json::Json {R"( { "policy": "other/name/version" } )"}, failure()),
                                         StorePostT(json::Json {R"( { "policy": "pol/name/version" } )"}, failure()),
                                         StorePostT(json::Json {R"( { "policy": "policy/name/version/ext" } )"},
                                                    failure()),
                                         StorePostT(json::Json {R"( { "policy": "policy/name" } )"}, failure()),
                                         StorePostT(json::Json {R"( { "policy": "policy/" } )"}, failure()),
                                         StorePostT(json::Json {R"( { "policy": "policy//0" } )"}, failure()),
                                         StorePostT(json::Json {R"( { "policy": "policy/name/0" } )"}, failure([](auto policy){
                                                EXPECT_CALL(*policy, create(base::Name {"policy/name/0"})).WillOnce(::testing::Return(base::Error {}));
                                         })),
                                         StorePostT(json::Json {R"( { "policy": "policy/name/0" } )"}, success([](auto policy){
                                                EXPECT_CALL(*policy, create(base::Name {"policy/name/0"})).WillOnce(::testing::Return(std::nullopt));
                                         }))));
