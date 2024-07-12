#include <gtest/gtest.h>

#include <builder/mockValidator.hpp>
#include <store/mockStore.hpp>

#include <api/policy/policy.hpp>

using namespace store::mocks;
using namespace builder::mocks;

namespace
{
const base::Name POLICY_NAME("policy/name/version");

const store::Doc POLICY_DOC {R"({
    "name": "policy/name/version",
    "hash": "4112711263806056918",
    "assets": [
        "decoder/system/0",
        "decoder/wazuh/0",
        "decoder/user/0"
    ],
    "default_parents": {
        "user": ["decoder/system/0"]
    }
})"};

const base::Name POLICY_NAME_2("policy/name/version2");

const store::Doc POLICY_DOC_2 {R"({
    "name": "policy/name/version2",
    "hash": "4112711263806056918",
    "assets": [
        "decoder/system/0",
        "decoder/user/0",
        "decoder/wazuh/0"
    ],
    "default_parents": {
        "user": ["decoder/system/0"]
    }
})"};

const std::string POLICY_DOC_HASH = "4112711263806056918";

const std::string POLICY_YML_ALL {R"(policy: policy/name/version
hash: 4112711263806056918
assets:
  - decoder/system/0
  - decoder/user/0
  - decoder/wazuh/0
default_parents:
  - user: decoder/system/0
)"};

const std::string POLICY_YML_SYS {R"(policy: policy/name/version
hash: 4112711263806056918
assets:
  - decoder/system/0
)"};

const std::string POLICY_YML_USR {R"(policy: policy/name/version
hash: 4112711263806056918
assets:
  - decoder/user/0
default_parents:
  - user: decoder/system/0
)"};

const std::string POLICY_YML_WZH {R"(policy: policy/name/version
hash: 4112711263806056918
assets:
  - decoder/wazuh/0
)"};

const std::string POLICY_YML_OTHER {R"(policy: policy/name/version
hash: 4112711263806056918
)"};

// Avoid string comparison issues with json
MATCHER_P(EqualsJson, expectedJson, "is not equal to expected JSON")
{
    return store::Doc {arg} == store::Doc {expectedJson};
}

void expectNsPolicy(std::shared_ptr<MockStore> store)
{
    EXPECT_CALL(*store, getNamespace({"decoder/system/0"}))
        .WillRepeatedly(testing::Return(storeGetNamespaceResp("system")));
    EXPECT_CALL(*store, getNamespace({"decoder/wazuh/0"}))
        .WillRepeatedly(testing::Return(storeGetNamespaceResp("wazuh")));
    EXPECT_CALL(*store, getNamespace({"decoder/user/0"}))
        .WillRepeatedly(testing::Return(storeGetNamespaceResp("user")));
}

template<typename T>
class PolicyTest : public ::testing::TestWithParam<T>
{
protected:
    std::shared_ptr<MockStore> m_store;
    std::shared_ptr<MockValidator> m_validator;
    std::unique_ptr<api::policy::Policy> m_policyManager;

    void SetUp() override
    {
        m_store = std::make_shared<MockStore>();
        m_validator = std::make_shared<MockValidator>();
        m_policyManager = std::make_unique<api::policy::Policy>(m_store, m_validator);
    }

    void TearDown() override
    {
        m_store.reset();
        m_validator.reset();
    }
};

template<typename Ret = base::OptError>
using ExpectedFn = std::function<Ret(std::shared_ptr<MockStore>, std::shared_ptr<MockValidator>)>;
using Behaviour = std::function<void(std::shared_ptr<MockStore>, std::shared_ptr<MockValidator>)>;

ExpectedFn<> success(Behaviour behaviour = nullptr)
{
    return [behaviour](auto store, auto validator)
    {
        if (behaviour)
        {
            behaviour(store, validator);
        }
        return base::noError();
    };
}
ExpectedFn<> failure(Behaviour behaviour = nullptr)
{
    return [behaviour](auto store, auto validator)
    {
        if (behaviour)
        {
            behaviour(store, validator);
        }
        return base::Error {};
    };
}

template<typename Ret>
using BehaviourRet = std::function<base::RespOrError<Ret>(std::shared_ptr<MockStore>, std::shared_ptr<MockValidator>)>;

template<typename Ret>
ExpectedFn<base::RespOrError<Ret>> success(BehaviourRet<Ret> behaviour = nullptr)
{
    return [behaviour](auto store, auto validator) -> base::RespOrError<Ret>
    {
        if (behaviour)
        {
            return behaviour(store, validator);
        }

        return Ret {};
    };
}
template<typename Ret>
ExpectedFn<base::RespOrError<Ret>> failure(Behaviour behaviour = nullptr)
{
    return [behaviour](auto store, auto validator)
    {
        if (behaviour)
        {
            behaviour(store, validator);
        }
        return base::Error {};
    };
}

} // namespace

/*******************************************************************************
 * Build Policy class
 ******************************************************************************/
TEST(PolicyTest, Build)
{
    auto store = std::make_shared<MockStore>();
    auto validator = std::make_shared<MockValidator>();
    std::shared_ptr<api::policy::Policy> policyManager;
    ASSERT_NO_THROW(policyManager = std::make_shared<api::policy::Policy>(store, validator));
    ASSERT_TRUE(policyManager);
}

TEST(PolicyTest, BuildFail)
{
    std::shared_ptr<MockStore> store = nullptr;
    auto validator = std::make_shared<MockValidator>();
    std::shared_ptr<api::policy::Policy> policyManager;
    ASSERT_THROW(policyManager = std::make_shared<api::policy::Policy>(store, validator), std::runtime_error);

    store = std::make_shared<MockStore>();
    validator = nullptr;
    ASSERT_THROW(policyManager = std::make_shared<api::policy::Policy>(store, validator), std::runtime_error);
}

/*******************************************************************************
 * Test create policy
 ******************************************************************************/
using CreateT = std::tuple<base::Name, ExpectedFn<>>;
using CreatePolicy = PolicyTest<CreateT>;
TEST_P(CreatePolicy, Create)
{
    auto [policy, expectedFn] = GetParam();

    auto expected = expectedFn(m_store, m_validator);
    auto res = m_policyManager->create(policy);
    if (base::isError(expected))
    {
        ASSERT_TRUE(base::isError(res));
    }
    else
    {
        ASSERT_FALSE(base::isError(res)) << "Error: " << base::getError(res).message << std::endl;
    }
}

INSTANTIATE_TEST_SUITE_P(
    PolicyTest,
    CreatePolicy,
    testing::Values(
        // Invalid names
        CreateT("invalidName", failure()),
        CreateT("pol/icy", failure()),
        CreateT("policy/noVersion", failure()),
        CreateT("policy/name/version/extraPart", failure()),
        CreateT("\n", failure()),
        CreateT("poLICY/name/version", failure()),
        // Already exists
        CreateT(POLICY_NAME,
                failure([](auto store, auto)
                        { EXPECT_CALL(*store, existsInternalDoc(POLICY_NAME)).WillOnce(::testing::Return(true)); })),
        // Validation fail
        CreateT(POLICY_NAME,
                failure(
                    [](auto store, auto validator)
                    {
                        EXPECT_CALL(*store, existsInternalDoc(POLICY_NAME)).WillOnce(::testing::Return(false));
                        EXPECT_CALL(*validator, validatePolicy(testing::_))
                            .WillOnce(::testing::Return(validateError()));
                    })),
        // Upsert fail
        CreateT(POLICY_NAME,
                failure(
                    [](auto store, auto validator)
                    {
                        EXPECT_CALL(*store, existsInternalDoc(POLICY_NAME)).WillOnce(::testing::Return(false));
                        EXPECT_CALL(*validator, validatePolicy(testing::_)).WillOnce(::testing::Return(validateOk()));
                        EXPECT_CALL(*store, upsertInternalDoc(POLICY_NAME, testing::_))
                            .WillOnce(::testing::Return(storeError()));
                    })),
        // Success
        CreateT(POLICY_NAME,
                success(
                    [](auto store, auto validator)
                    {
                        EXPECT_CALL(*store, existsInternalDoc(POLICY_NAME)).WillOnce(::testing::Return(false));
                        EXPECT_CALL(*validator, validatePolicy(testing::_)).WillOnce(::testing::Return(validateOk()));
                        EXPECT_CALL(*store, upsertInternalDoc(POLICY_NAME, testing::_))
                            .WillOnce(::testing::Return(storeOk()));
                    }))));

/*******************************************************************************
 * Test delete policy
 ******************************************************************************/
using DeleteT = std::tuple<base::Name, ExpectedFn<>>;
using DeletePolicy = PolicyTest<DeleteT>;
TEST_P(DeletePolicy, Delete)
{
    auto [policy, expectedFn] = GetParam();

    auto expected = expectedFn(m_store, m_validator);
    auto res = m_policyManager->del(policy);
    if (base::isError(expected))
    {
        ASSERT_TRUE(base::isError(res));
    }
    else
    {
        ASSERT_FALSE(base::isError(res)) << "Error: " << base::getError(res).message << std::endl;
    }
}

INSTANTIATE_TEST_SUITE_P(
    PolicyTest,
    DeletePolicy,
    testing::Values(
        // Invalid names
        DeleteT("invalidName", failure()),
        DeleteT("pol/icy", failure()),
        DeleteT("policy/noVersion", failure()),
        DeleteT("policy/name/version/extraPart", failure()),
        DeleteT("\n", failure()),
        DeleteT("poLICY/name/version", failure()),
        // Store error
        DeleteT(POLICY_NAME,
                failure(
                    [](auto store, auto) {
                        EXPECT_CALL(*store, deleteInternalDoc(POLICY_NAME)).WillOnce(::testing::Return(storeError()));
                    })),
        // Success
        DeleteT(POLICY_NAME,
                success(
                    [](auto store, auto) {
                        EXPECT_CALL(*store, deleteInternalDoc(POLICY_NAME)).WillOnce(::testing::Return(std::nullopt));
                    }))));

/*******************************************************************************
 * Test get policy
 ******************************************************************************/
using GetT = std::tuple<base::Name, std::vector<store::NamespaceId>, ExpectedFn<base::RespOrError<std::string>>>;
using GetPolicy = PolicyTest<GetT>;

TEST_P(GetPolicy, Get)
{
    auto [policy, namespaces, expectedFn] = GetParam();

    auto expected = expectedFn(m_store, m_validator);
    auto res = m_policyManager->get(policy, namespaces);
    if (base::isError(expected))
    {
        ASSERT_TRUE(base::isError(res));
    }
    else
    {
        ASSERT_FALSE(base::isError(res)) << "Error: " << base::getError(res).message << std::endl;
        // TODO: Update use cases
        ASSERT_EQ(base::getResponse<std::string>(res), base::getResponse<std::string>(expected));
    }
}

INSTANTIATE_TEST_SUITE_P(PolicyTest,
                         GetPolicy,
                         testing::Values(
                             // Invalid names
                             GetT("invalidName", {}, failure<std::string>()),
                             GetT("pol/icy", {}, failure<std::string>()),
                             GetT("policy/noVersion", {}, failure<std::string>()),
                             GetT("policy/name/version/extraPart", {}, failure<std::string>()),
                             GetT("\n", {}, failure<std::string>()),
                             GetT("poLICY/name/version", {}, failure<std::string>()),
                             // Store error
                             GetT(POLICY_NAME,
                                  {},
                                  failure<std::string>(
                                      [](auto store, auto) {
                                          EXPECT_CALL(*store, readInternalDoc(POLICY_NAME))
                                              .WillOnce(::testing::Return(storeReadError<store::Doc>()));
                                      })),
                             // Success no namespaces
                             GetT(POLICY_NAME,
                                  {},
                                  success<std::string>(
                                      [](auto store, auto)
                                      {
                                          EXPECT_CALL(*store, readInternalDoc(POLICY_NAME))
                                              .WillOnce(::testing::Return(storeReadDocResp(POLICY_DOC)));
                                          expectNsPolicy(store);
                                          return POLICY_YML_ALL;
                                      })),
                             // Success with namespaces
                             GetT(POLICY_NAME,
                                  {"user"},
                                  success<std::string>(
                                      [](auto store, auto)
                                      {
                                          EXPECT_CALL(*store, readInternalDoc(POLICY_NAME))
                                              .WillOnce(::testing::Return(storeReadDocResp(POLICY_DOC)));
                                          expectNsPolicy(store);
                                          return POLICY_YML_USR;
                                      })),
                             GetT(POLICY_NAME,
                                  {"nonexists"},
                                  success<std::string>(
                                      [](auto store, auto)
                                      {
                                          EXPECT_CALL(*store, readInternalDoc(POLICY_NAME))
                                              .WillOnce(::testing::Return(storeReadDocResp(POLICY_DOC)));
                                          expectNsPolicy(store);
                                          return POLICY_YML_OTHER;
                                      })),
                             GetT(POLICY_NAME,
                                  {"user", "wazuh", "system"},
                                  success<std::string>(
                                      [](auto store, auto)
                                      {
                                          EXPECT_CALL(*store, readInternalDoc(POLICY_NAME))
                                              .WillOnce(::testing::Return(storeReadDocResp(POLICY_DOC)));
                                          expectNsPolicy(store);
                                          return POLICY_YML_ALL;
                                      }))));

/*******************************************************************************
 * Test list policies
 ******************************************************************************/
using ListT = std::tuple<ExpectedFn<base::RespOrError<std::vector<base::Name>>>>;
using ListPolicy = PolicyTest<ListT>;

TEST_P(ListPolicy, List)
{
    auto [expectedFn] = GetParam();

    auto expected = expectedFn(m_store, m_validator);
    auto res = m_policyManager->list();
    if (base::isError(expected))
    {
        ASSERT_TRUE(base::isError(res));
    }
    else
    {
        ASSERT_FALSE(base::isError(res)) << "Error: " << base::getError(res).message << std::endl;
        ASSERT_EQ(base::getResponse<std::vector<base::Name>>(res),
                  base::getResponse<std::vector<base::Name>>(expected));
    }
}

INSTANTIATE_TEST_SUITE_P(
    PolicyTest,
    ListPolicy,
    testing::Values(
        // Store error
        ListT(failure<std::vector<base::Name>>(
            [](auto store, auto) {
                EXPECT_CALL(*store, readInternalCol({"policy"}))
                    .WillOnce(::testing::Return(storeReadError<store::Col>()));
            })),
        // Success
        ListT(success<std::vector<base::Name>>(
            [](auto store, auto)
            {
                EXPECT_CALL(*store, readInternalCol({"policy"})).WillOnce(::testing::Return(storeReadColResp()));
                return std::vector<base::Name> {};
            })),
        ListT(success<std::vector<base::Name>>(
            [](auto store, auto)
            {
                std::vector<base::Name> expectedCols = {"policy/name1", "policy/name2"};
                std::vector<base::Name> expected;
                EXPECT_CALL(*store, readInternalCol({"policy"}))
                    .WillOnce(::testing::Return(storeReadColResp(expectedCols)));
                for (auto& expectedCol : expectedCols)
                {
                    auto expectedName = expectedCol + "0";
                    expected.emplace_back(expectedName);
                    EXPECT_CALL(*store, readInternalCol(expectedCol))
                        .WillOnce(::testing::Return(storeReadColResp(expectedName)));
                }
                return expected;
            }))));

/*******************************************************************************
 * Add asset to policy
 ******************************************************************************/
using AddAssetT = std::tuple<base::Name, store::NamespaceId, base::Name, ExpectedFn<>>;
using AddAsset = PolicyTest<AddAssetT>;

TEST_P(AddAsset, Add)
{
    auto [policy, namespaceId, asset, expectedFn] = GetParam();

    auto expected = expectedFn(m_store, m_validator);
    auto res = m_policyManager->addAsset(policy, namespaceId, asset);
    if (base::isError(expected))
    {
        ASSERT_TRUE(base::isError(res));
    }
    else
    {
        ASSERT_FALSE(base::isError(res)) << "Error: " << base::getError(res).message << std::endl;
    }
}

INSTANTIATE_TEST_SUITE_P(
    PolicyTest,
    AddAsset,
    testing::Values(
        // Invalid policy names
        AddAssetT("invalidName", "namespace", "asset", failure()),
        AddAssetT("pol/icy", "namespace", "asset", failure()),
        AddAssetT("policy/noVersion", "namespace", "asset", failure()),
        AddAssetT("policy/name/version/extraPart", "namespace", "asset", failure()),
        AddAssetT("\n", "namespace", "asset", failure()),
        AddAssetT("poLICY/name/version", "namespace", "asset", failure()),
        // Store get policy error
        AddAssetT(POLICY_NAME,
                  "namespace",
                  "asset",
                  failure(
                      [](auto store, auto) {
                          EXPECT_CALL(*store, readInternalDoc(POLICY_NAME))
                              .WillOnce(::testing::Return(storeReadError<store::Doc>()));
                      })),
        // Asset already exists
        AddAssetT(POLICY_NAME,
                  "user",
                  "decoder/user/0",
                  failure(
                      [](auto store, auto)
                      {
                          EXPECT_CALL(*store, readInternalDoc(POLICY_NAME))
                              .WillOnce(::testing::Return(storeReadDocResp(POLICY_DOC)));
                          expectNsPolicy(store);
                      })),
        // Add asset when exists in different namespace
        AddAssetT(POLICY_NAME,
                  "user",
                  "decoder/system/0",
                  failure(
                      [](auto store, auto)
                      {
                          EXPECT_CALL(*store, readInternalDoc(POLICY_NAME))
                              .WillOnce(::testing::Return(storeReadDocResp(POLICY_DOC)));
                          expectNsPolicy(store);
                      })),
        // Validation warning
        AddAssetT(POLICY_NAME,
                  "user",
                  "decoder/user/1",
                  success(
                      [](auto store, auto validator)
                      {
                          EXPECT_CALL(*store, readInternalDoc(POLICY_NAME))
                              .WillOnce(::testing::Return(storeReadDocResp(POLICY_DOC)));
                          expectNsPolicy(store);
                          EXPECT_CALL(*store, getNamespace({"decoder/user/1"}))
                              .WillRepeatedly(testing::Return(storeGetNamespaceResp("user")));
                          EXPECT_CALL(*validator, validatePolicy(testing::_))
                              .WillOnce(::testing::Return(validateError()));
                      })),
        // Store upsert error
        AddAssetT(POLICY_NAME,
                  "user",
                  "decoder/user/1",
                  failure(
                      [](auto store, auto validator)
                      {
                          EXPECT_CALL(*store, readInternalDoc(POLICY_NAME))
                              .WillOnce(::testing::Return(storeReadDocResp(POLICY_DOC)));
                          expectNsPolicy(store);
                          EXPECT_CALL(*store, getNamespace({"decoder/user/1"}))
                              .WillRepeatedly(testing::Return(storeGetNamespaceResp("user")));
                          EXPECT_CALL(*validator, validatePolicy(testing::_)).WillOnce(::testing::Return(validateOk()));
                          EXPECT_CALL(*store, upsertInternalDoc(POLICY_NAME, testing::_))
                              .WillOnce(::testing::Return(storeError()));
                      })),
        // Success
        AddAssetT(POLICY_NAME,
                  "user",
                  "decoder/user/1",
                  success(
                      [](auto store, auto validator)
                      {
                          EXPECT_CALL(*store, readInternalDoc(POLICY_NAME))
                              .WillOnce(::testing::Return(storeReadDocResp(POLICY_DOC)));
                          expectNsPolicy(store);
                          EXPECT_CALL(*store, getNamespace({"decoder/user/1"}))
                              .WillRepeatedly(testing::Return(storeGetNamespaceResp("user")));
                          EXPECT_CALL(*validator, validatePolicy(testing::_)).WillOnce(::testing::Return(validateOk()));
                          EXPECT_CALL(*store, upsertInternalDoc(POLICY_NAME, testing::_))
                              .WillOnce(::testing::Return(storeOk()));
                      }))));

/*******************************************************************************
 * Delete asset from policy
 ******************************************************************************/
using DeleteAssetT = std::tuple<base::Name, store::NamespaceId, base::Name, ExpectedFn<>>;
using DeleteAsset = PolicyTest<DeleteAssetT>;

TEST_P(DeleteAsset, Delete)
{
    auto [policy, namespaceId, asset, expectedFn] = GetParam();

    auto expected = expectedFn(m_store, m_validator);
    auto res = m_policyManager->delAsset(policy, namespaceId, asset);
    if (base::isError(expected))
    {
        ASSERT_TRUE(base::isError(res));
    }
    else
    {
        ASSERT_FALSE(base::isError(res)) << "Error: " << base::getError(res).message << std::endl;
    }
}

INSTANTIATE_TEST_SUITE_P(PolicyTest,
                         DeleteAsset,
                         testing::Values(
                             // Invalid policy names
                             DeleteAssetT("invalidName", "namespace", "asset", failure()),
                             DeleteAssetT("pol/icy", "namespace", "asset", failure()),
                             DeleteAssetT("policy/noVersion", "namespace", "asset", failure()),
                             DeleteAssetT("policy/name/version/extraPart", "namespace", "asset", failure()),
                             DeleteAssetT("\n", "namespace", "asset", failure()),
                             DeleteAssetT("poLICY/name/version", "namespace", "asset", failure()),
                             // Store get policy error
                             DeleteAssetT(POLICY_NAME,
                                          "namespace",
                                          "asset",
                                          failure(
                                              [](auto store, auto) {
                                                  EXPECT_CALL(*store, readInternalDoc(POLICY_NAME))
                                                      .WillOnce(::testing::Return(storeReadError<store::Doc>()));
                                              })),
                             // Asset not found
                             DeleteAssetT(POLICY_NAME,
                                          "user",
                                          "decoder/user/1",
                                          failure(
                                              [](auto store, auto)
                                              {
                                                  EXPECT_CALL(*store, readInternalDoc(POLICY_NAME))
                                                      .WillOnce(::testing::Return(storeReadDocResp(POLICY_DOC)));
                                                  expectNsPolicy(store);
                                              })),
                             // Asset found in different namespace
                             DeleteAssetT(POLICY_NAME,
                                          "user",
                                          "decoder/system/0",
                                          failure(
                                              [](auto store, auto)
                                              {
                                                  EXPECT_CALL(*store, readInternalDoc(POLICY_NAME))
                                                      .WillOnce(::testing::Return(storeReadDocResp(POLICY_DOC)));
                                                  expectNsPolicy(store);
                                              })),
                             // Validation warning
                             DeleteAssetT(POLICY_NAME,
                                          "user",
                                          "decoder/user/0",
                                          success(
                                              [](auto store, auto validator)
                                              {
                                                  EXPECT_CALL(*store, readInternalDoc(POLICY_NAME))
                                                      .WillOnce(::testing::Return(storeReadDocResp(POLICY_DOC)));
                                                  expectNsPolicy(store);
                                                  EXPECT_CALL(*validator, validatePolicy(testing::_))
                                                      .WillOnce(::testing::Return(validateError()));
                                              })),
                             // Store upsert error
                             DeleteAssetT(POLICY_NAME,
                                          "user",
                                          "decoder/user/0",
                                          failure(
                                              [](auto store, auto validator)
                                              {
                                                  EXPECT_CALL(*store, readInternalDoc(POLICY_NAME))
                                                      .WillOnce(::testing::Return(storeReadDocResp(POLICY_DOC)));
                                                  expectNsPolicy(store);
                                                  EXPECT_CALL(*validator, validatePolicy(testing::_))
                                                      .WillOnce(::testing::Return(validateOk()));
                                                  EXPECT_CALL(*store, upsertInternalDoc(POLICY_NAME, testing::_))
                                                      .WillOnce(::testing::Return(storeError()));
                                              })),
                             // Success
                             DeleteAssetT(POLICY_NAME,
                                          "user",
                                          "decoder/user/0",
                                          success(
                                              [](auto store, auto validator)
                                              {
                                                  EXPECT_CALL(*store, readInternalDoc(POLICY_NAME))
                                                      .WillOnce(::testing::Return(storeReadDocResp(POLICY_DOC)));
                                                  expectNsPolicy(store);
                                                  EXPECT_CALL(*validator, validatePolicy(testing::_))
                                                      .WillOnce(::testing::Return(validateOk()));
                                                  EXPECT_CALL(*store, upsertInternalDoc(POLICY_NAME, testing::_))
                                                      .WillOnce(::testing::Return(storeOk()));
                                              }))));

/*******************************************************************************
 * List assets from policy
 ******************************************************************************/
using ListAssetsT = std::tuple<base::Name, store::NamespaceId, ExpectedFn<base::RespOrError<std::list<base::Name>>>>;
using ListAssets = PolicyTest<ListAssetsT>;

TEST_P(ListAssets, List)
{
    auto [policy, namespaceId, expectedFn] = GetParam();

    auto expected = expectedFn(m_store, m_validator);
    auto res = m_policyManager->listAssets(policy, namespaceId);
    if (base::isError(expected))
    {
        ASSERT_TRUE(base::isError(res));
    }
    else
    {
        ASSERT_FALSE(base::isError(res)) << "Error: " << base::getError(res).message << std::endl;
        ASSERT_EQ(base::getResponse<std::list<base::Name>>(res), base::getResponse<std::list<base::Name>>(expected));
    }
}

INSTANTIATE_TEST_SUITE_P(
    PolicyTest,
    ListAssets,
    testing::Values(
        // Invalid policy names
        ListAssetsT("invalidName", "namespace", failure<std::list<base::Name>>()),
        ListAssetsT("pol/icy", "namespace", failure<std::list<base::Name>>()),
        ListAssetsT("policy/noVersion", "namespace", failure<std::list<base::Name>>()),
        ListAssetsT("policy/name/version/extraPart", "namespace", failure<std::list<base::Name>>()),
        ListAssetsT("\n", "namespace", failure<std::list<base::Name>>()),
        ListAssetsT("poLICY/name/version", "namespace", failure<std::list<base::Name>>()),
        // Store get policy error
        ListAssetsT(POLICY_NAME,
                    "namespace",
                    failure<std::list<base::Name>>(
                        [](auto store, auto) {
                            EXPECT_CALL(*store, readInternalDoc(POLICY_NAME))
                                .WillOnce(::testing::Return(storeReadError<store::Doc>()));
                        })),
        // Success
        ListAssetsT(POLICY_NAME,
                    "system",
                    success<std::list<base::Name>>(
                        [](auto store, auto)
                        {
                            EXPECT_CALL(*store, readInternalDoc(POLICY_NAME))
                                .WillOnce(::testing::Return(storeReadDocResp(POLICY_DOC)));
                            expectNsPolicy(store);
                            return std::list<base::Name> {"decoder/system/0"};
                        })),
        ListAssetsT(POLICY_NAME,
                    "nonexists",
                    success<std::list<base::Name>>(
                        [](auto store, auto)
                        {
                            EXPECT_CALL(*store, readInternalDoc(POLICY_NAME))
                                .WillOnce(::testing::Return(storeReadDocResp(POLICY_DOC)));
                            expectNsPolicy(store);
                            return std::list<base::Name> {};
                        }))));

/*******************************************************************************
 * Get default parent from namespace in policy
 ******************************************************************************/
using GetDefaultParentT =
    std::tuple<base::Name, store::NamespaceId, ExpectedFn<base::RespOrError<std::list<base::Name>>>>;
using GetDefaultParent = PolicyTest<GetDefaultParentT>;

TEST_P(GetDefaultParent, Get)
{
    auto [policy, namespaceId, expectedFn] = GetParam();

    auto expected = expectedFn(m_store, m_validator);
    auto res = m_policyManager->getDefaultParent(policy, namespaceId);
    if (base::isError(expected))
    {
        ASSERT_TRUE(base::isError(res));
    }
    else
    {
        ASSERT_FALSE(base::isError(res)) << "Error: " << base::getError(res).message << std::endl;
        ASSERT_EQ(base::getResponse<std::list<base::Name>>(res).size(),
                  base::getResponse<std::list<base::Name>>(expected).size());
    }
}

INSTANTIATE_TEST_SUITE_P(
    PolicyTest,
    GetDefaultParent,
    testing::Values(
        // Invalid policy names
        GetDefaultParentT("invalidName", "namespace", failure<std::list<base::Name>>()),
        GetDefaultParentT("pol/icy", "namespace", failure<std::list<base::Name>>()),
        GetDefaultParentT("policy/noVersion", "namespace", failure<std::list<base::Name>>()),
        GetDefaultParentT("policy/name/version/extraPart", "namespace", failure<std::list<base::Name>>()),
        GetDefaultParentT("\n", "namespace", failure<std::list<base::Name>>()),
        GetDefaultParentT("poLICY/name/version", "namespace", failure<std::list<base::Name>>()),
        // Store get policy error
        GetDefaultParentT(POLICY_NAME,
                          "unused",
                          failure<std::list<base::Name>>(
                              [](auto store, auto) {
                                  EXPECT_CALL(*store, readInternalDoc(POLICY_NAME))
                                      .WillOnce(::testing::Return(storeReadError<store::Doc>()));
                              })),
        // Namespace not found
        GetDefaultParentT(POLICY_NAME,
                          "nonexists",
                          failure<std::list<base::Name>>(
                              [](auto store, auto)
                              {
                                  EXPECT_CALL(*store, readInternalDoc(POLICY_NAME))
                                      .WillOnce(::testing::Return(base::Error {"error"}));
                                  expectNsPolicy(store);
                              })),
        // Success
        GetDefaultParentT(POLICY_NAME,
                          "user",
                          success<std::list<base::Name>>(
                              [](auto store, auto)
                              {
                                  EXPECT_CALL(*store, readInternalDoc(POLICY_NAME))
                                      .WillOnce(::testing::Return(storeReadDocResp(POLICY_DOC)));
                                  expectNsPolicy(store);
                                  return std::list<base::Name> {"decoder/system/0"};
                              }))));

/*******************************************************************************
 * Set default parent from namespace in policy
 ******************************************************************************/
using SetDefaultParentT = std::tuple<base::Name, store::NamespaceId, base::Name, ExpectedFn<>>;
using SetDefaultParent = PolicyTest<SetDefaultParentT>;

TEST_P(SetDefaultParent, Set)
{
    auto [policy, namespaceId, defaultParent, expectedFn] = GetParam();

    auto expected = expectedFn(m_store, m_validator);
    auto res = m_policyManager->setDefaultParent(policy, namespaceId, defaultParent);
    if (base::isError(expected))
    {
        ASSERT_TRUE(base::isError(res));
    }
    else
    {
        ASSERT_FALSE(base::isError(res)) << "Error: " << base::getError(res).message << std::endl;
    }
}

INSTANTIATE_TEST_SUITE_P(
    PolicyTest,
    SetDefaultParent,
    testing::Values(
        // Invalid policy names
        SetDefaultParentT("invalidName", "namespace", "defaultParent", failure()),
        SetDefaultParentT("pol/icy", "namespace", "defaultParent", failure()),
        SetDefaultParentT("policy/noVersion", "namespace", "defaultParent", failure()),
        SetDefaultParentT("policy/name/version/extraPart", "namespace", "defaultParent", failure()),
        SetDefaultParentT("\n", "namespace", "defaultParent", failure()),
        SetDefaultParentT("poLICY/name/version", "namespace", "defaultParent", failure()),
        // Store get policy error
        SetDefaultParentT(POLICY_NAME,
                          "unused",
                          "unused",
                          failure(
                              [](auto store, auto) {
                                  EXPECT_CALL(*store, readInternalDoc(POLICY_NAME))
                                      .WillOnce(::testing::Return(storeReadError<store::Doc>()));
                              })),
        // Already set
        SetDefaultParentT(POLICY_NAME,
                          "user",
                          "decoder/wazuh/0",
                          failure(
                              [](auto store, auto validator)
                              {
                                  EXPECT_CALL(*store, readInternalDoc(POLICY_NAME))
                                      .WillOnce(::testing::Return(storeReadDocResp(POLICY_DOC)));
                                  EXPECT_CALL(*validator, validatePolicy(testing::_))
                                      .WillOnce(::testing::Return(std::nullopt));
                                  EXPECT_CALL(*store, upsertInternalDoc(testing::_, testing::_))
                                      .WillOnce(::testing::Return(base::Error {"error"}));
                                  expectNsPolicy(store);
                              })),
        // Validation warning
        SetDefaultParentT(POLICY_NAME,
                          "wazuh",
                          "decoder/system/0",
                          success(
                              [](auto store, auto validator)
                              {
                                  EXPECT_CALL(*store, readInternalDoc(POLICY_NAME))
                                      .WillOnce(::testing::Return(storeReadDocResp(POLICY_DOC)));
                                  expectNsPolicy(store);
                                  EXPECT_CALL(*validator, validatePolicy(testing::_))
                                      .WillOnce(::testing::Return(validateError()));
                              })),
        // Store upsert error
        SetDefaultParentT(POLICY_NAME,
                          "wazuh",
                          "decoder/system/0",
                          failure(
                              [](auto store, auto validator)
                              {
                                  EXPECT_CALL(*store, readInternalDoc(POLICY_NAME))
                                      .WillOnce(::testing::Return(storeReadDocResp(POLICY_DOC)));
                                  expectNsPolicy(store);
                                  EXPECT_CALL(*validator, validatePolicy(testing::_))
                                      .WillOnce(::testing::Return(validateOk()));
                                  EXPECT_CALL(*store, upsertInternalDoc(POLICY_NAME, testing::_))
                                      .WillOnce(::testing::Return(storeError()));
                              })),
        // Success
        SetDefaultParentT(POLICY_NAME,
                          "wazuh",
                          "decoder/system/0",
                          success(
                              [](auto store, auto validator)
                              {
                                  EXPECT_CALL(*store, readInternalDoc(POLICY_NAME))
                                      .WillOnce(::testing::Return(storeReadDocResp(POLICY_DOC)));
                                  expectNsPolicy(store);
                                  EXPECT_CALL(*validator, validatePolicy(testing::_))
                                      .WillOnce(::testing::Return(validateOk()));
                                  EXPECT_CALL(*store, upsertInternalDoc(POLICY_NAME, testing::_))
                                      .WillOnce(::testing::Return(storeOk()));
                              }))));

/*******************************************************************************
 * Delete default parent from namespace in policy
 ******************************************************************************/
using DeleteDefaultParentT = std::tuple<base::Name, store::NamespaceId, base::Name, ExpectedFn<>>;
using DeleteDefaultParent = PolicyTest<DeleteDefaultParentT>;

TEST_P(DeleteDefaultParent, Delete)
{
    auto [policy, namespaceId, parent, expectedFn] = GetParam();

    auto expected = expectedFn(m_store, m_validator);
    auto res = m_policyManager->delDefaultParent(policy, namespaceId, parent);
    if (base::isError(expected))
    {
        ASSERT_TRUE(base::isError(res));
    }
    else
    {
        ASSERT_FALSE(base::isError(res)) << "Error: " << base::getError(res).message << std::endl;
    }
}

INSTANTIATE_TEST_SUITE_P(
    PolicyTest,
    DeleteDefaultParent,
    testing::Values(
        // Invalid policy names
        DeleteDefaultParentT("invalidName", "namespace", "parent", failure()),
        DeleteDefaultParentT("pol/icy", "namespace", "parent", failure()),
        DeleteDefaultParentT("policy/noVersion", "namespace", "parent", failure()),
        DeleteDefaultParentT("policy/name/version/extraPart", "namespace", "parent", failure()),
        DeleteDefaultParentT("\n", "namespace", "parent", failure()),
        DeleteDefaultParentT("poLICY/name/version", "namespace", "parent", failure()),
        // Store get policy error
        DeleteDefaultParentT(POLICY_NAME,
                             "unused",
                             "parent",
                             failure(
                                 [](auto store, auto) {
                                     EXPECT_CALL(*store, readInternalDoc(POLICY_NAME))
                                         .WillOnce(::testing::Return(storeReadError<store::Doc>()));
                                 })),
        // Namespace not found
        DeleteDefaultParentT(POLICY_NAME,
                             "system",
                             "parent",
                             failure(
                                 [](auto store, auto validator)
                                 {
                                     EXPECT_CALL(*store, readInternalDoc(POLICY_NAME))
                                         .WillOnce(::testing::Return(storeReadDocResp(POLICY_DOC)));
                                     expectNsPolicy(store);
                                 })),
        // Parent not found in namespace
        DeleteDefaultParentT(POLICY_NAME,
                             "user",
                             "parent",
                             failure(
                                 [](auto store, auto validator)
                                 {
                                     EXPECT_CALL(*store, readInternalDoc(POLICY_NAME))
                                         .WillOnce(::testing::Return(storeReadDocResp(POLICY_DOC)));
                                     expectNsPolicy(store);
                                 })),
        // Validation warning
        DeleteDefaultParentT(POLICY_NAME,
                             "user",
                             "decoder/system/0",
                             success(
                                 [](auto store, auto validator)
                                 {
                                     EXPECT_CALL(*store, readInternalDoc(POLICY_NAME))
                                         .WillOnce(::testing::Return(storeReadDocResp(POLICY_DOC)));
                                     EXPECT_CALL(*validator, validatePolicy(testing::_))
                                         .WillOnce(::testing::Return(validateError()));
                                     expectNsPolicy(store);
                                 })),
        // Store upsert error
        DeleteDefaultParentT(POLICY_NAME,
                             "user",
                             "decoder/system/0",
                             failure(
                                 [](auto store, auto validator)
                                 {
                                     EXPECT_CALL(*store, readInternalDoc(POLICY_NAME))
                                         .WillOnce(::testing::Return(storeReadDocResp(POLICY_DOC)));
                                     expectNsPolicy(store);
                                     EXPECT_CALL(*validator, validatePolicy(testing::_))
                                         .WillOnce(::testing::Return(validateOk()));
                                     EXPECT_CALL(*store, upsertInternalDoc(POLICY_NAME, testing::_))
                                         .WillOnce(::testing::Return(storeError()));
                                 })),
        // Success
        DeleteDefaultParentT(POLICY_NAME,
                             "user",
                             "decoder/system/0",
                             success(
                                 [](auto store, auto validator)
                                 {
                                     EXPECT_CALL(*store, readInternalDoc(POLICY_NAME))
                                         .WillOnce(::testing::Return(storeReadDocResp(POLICY_DOC)));
                                     expectNsPolicy(store);
                                     EXPECT_CALL(*validator, validatePolicy(testing::_))
                                         .WillOnce(::testing::Return(validateOk()));
                                     EXPECT_CALL(*store, upsertInternalDoc(POLICY_NAME, testing::_))
                                         .WillOnce(::testing::Return(storeOk()));
                                 }))));

/*******************************************************************************
 * List namespaces from policy
 ******************************************************************************/
using ListNamespacesT = std::tuple<base::Name, ExpectedFn<base::RespOrError<std::list<store::NamespaceId>>>>;
using ListNamespaces = PolicyTest<ListNamespacesT>;

TEST_P(ListNamespaces, List)
{
    auto [policy, expectedFn] = GetParam();

    auto expected = expectedFn(m_store, m_validator);
    auto res = m_policyManager->listNamespaces(policy);
    if (base::isError(expected))
    {
        ASSERT_TRUE(base::isError(res));
    }
    else
    {
        ASSERT_FALSE(base::isError(res)) << "Error: " << base::getError(res).message << std::endl;
        ASSERT_EQ(base::getResponse<std::list<store::NamespaceId>>(res),
                  base::getResponse<std::list<store::NamespaceId>>(expected));
    }
}

INSTANTIATE_TEST_SUITE_P(PolicyTest,
                         ListNamespaces,
                         testing::Values(
                             // Invalid policy names
                             ListNamespacesT("invalidName", failure<std::list<store::NamespaceId>>()),
                             ListNamespacesT("pol/icy", failure<std::list<store::NamespaceId>>()),
                             ListNamespacesT("policy/noVersion", failure<std::list<store::NamespaceId>>()),
                             ListNamespacesT("policy/name/version/extraPart", failure<std::list<store::NamespaceId>>()),
                             ListNamespacesT("\n", failure<std::list<store::NamespaceId>>()),
                             ListNamespacesT("poLICY/name/version", failure<std::list<store::NamespaceId>>()),
                             // Store get policy error
                             ListNamespacesT(POLICY_NAME,
                                             failure<std::list<store::NamespaceId>>(
                                                 [](auto store, auto) {
                                                     EXPECT_CALL(*store, readInternalDoc(POLICY_NAME))
                                                         .WillOnce(::testing::Return(storeReadError<store::Doc>()));
                                                 })),
                             // Success
                             ListNamespacesT(POLICY_NAME,
                                             success<std::list<store::NamespaceId>>(
                                                 [](auto store, auto)
                                                 {
                                                     EXPECT_CALL(*store, readInternalDoc(POLICY_NAME))
                                                         .WillOnce(::testing::Return(storeReadDocResp(POLICY_DOC)));
                                                     expectNsPolicy(store);
                                                     return std::list<store::NamespaceId> {"system", "user", "wazuh"};
                                                 }))));

/*******************************************************************************
 * Get the hash of the policy
 ******************************************************************************/

using GetHashT = std::tuple<base::Name, ExpectedFn<base::RespOrError<std::string>>>;
using GetHash = PolicyTest<GetHashT>;

TEST_P(GetHash, Get)
{
    auto [policy, expectedFn] = GetParam();

    auto expected = expectedFn(m_store, m_validator);
    auto res = m_policyManager->getHash(policy);
    if (base::isError(expected))
    {
        ASSERT_TRUE(base::isError(res));
    }
    else
    {
        ASSERT_FALSE(base::isError(res)) << "Error: " << base::getError(res).message << std::endl;
        ASSERT_EQ(base::getResponse<std::string>(res), base::getResponse<std::string>(expected));
    }
}

INSTANTIATE_TEST_SUITE_P(PolicyTest,
                         GetHash,
                         testing::Values(
                             // Invalid policy names
                             GetHashT("invalidName", failure<std::string>()),
                             GetHashT("pol/icy", failure<std::string>()),
                             GetHashT("policy/noVersion", failure<std::string>()),
                             GetHashT("policy/name/version/extraPart", failure<std::string>()),
                             GetHashT("\n", failure<std::string>()),
                             GetHashT("poLICY/name/version", failure<std::string>()),
                             // Store get policy error
                             GetHashT(POLICY_NAME,
                                      failure<std::string>(
                                          [](auto store, auto) {
                                              EXPECT_CALL(*store, readInternalDoc(POLICY_NAME))
                                                  .WillOnce(::testing::Return(storeReadError<store::Doc>()));
                                          })),
                             // Success
                             GetHashT(POLICY_NAME,
                                      success<std::string>(
                                          [](auto store, auto)
                                          {
                                              EXPECT_CALL(*store, readInternalDoc(POLICY_NAME))
                                                  .WillOnce(::testing::Return(storeReadDocResp(POLICY_DOC)));
                                              expectNsPolicy(store);
                                              return POLICY_DOC_HASH;
                                          }))));

/*******************************************************************************
 * Copy a policy
 ******************************************************************************/
using CopyT = std::tuple<base::Name, base::Name, ExpectedFn<>>;
using Copy = PolicyTest<CopyT>;

TEST_P(Copy, Copy)
{
    auto [policy, newPolicy, expectedFn] = GetParam();

    auto expected = expectedFn(m_store, m_validator);
    auto res = m_policyManager->copy(policy, newPolicy);
    if (base::isError(expected))
    {
        ASSERT_TRUE(base::isError(res));
    }
    else
    {
        ASSERT_FALSE(base::isError(res)) << "Error: " << base::getError(res).message << std::endl;
    }
}

INSTANTIATE_TEST_SUITE_P(
    PolicyTest,
    Copy,
    testing::Values(
        // Invalid policy names
        CopyT("invalidName", POLICY_NAME_2, failure()),
        CopyT("pol/icy", POLICY_NAME_2, failure()),
        CopyT("policy/noVersion", POLICY_NAME_2, failure()),
        CopyT("policy/name/version/extraPart", POLICY_NAME_2, failure()),
        CopyT("\n", POLICY_NAME_2, failure()),
        CopyT("poLICY/name/version", POLICY_NAME_2, failure()),
        // Invalid new policy names
        CopyT(POLICY_NAME, "invalidName", failure()),
        CopyT(POLICY_NAME, "pol/icy", failure()),
        CopyT(POLICY_NAME, "policy/noVersion", failure()),
        CopyT(POLICY_NAME, "policy/name/version/extraPart", failure()),
        CopyT(POLICY_NAME, "\n", failure()),
        CopyT(POLICY_NAME, "poLICY/name/version", failure()),
        // Store get policy error
        CopyT(POLICY_NAME,
              POLICY_NAME_2,
              failure(
                  [](auto store, auto) {
                      EXPECT_CALL(*store, readInternalDoc(POLICY_NAME))
                          .WillOnce(::testing::Return(storeReadError<store::Doc>()));
                  })),
        // Validator error
        CopyT(POLICY_NAME,
              POLICY_NAME_2,
              failure(
                  [](auto store, auto validator)
                  {
                      EXPECT_CALL(*store, readInternalDoc(POLICY_NAME))
                          .WillOnce(::testing::Return(storeReadDocResp(POLICY_DOC)));
                      expectNsPolicy(store);

                      EXPECT_CALL(*validator, validatePolicy(POLICY_DOC_2))
                          .WillOnce(::testing::Return(validateError()));
                  })),
        // Store upsert new policy error
        CopyT(POLICY_NAME,
              POLICY_NAME_2,
              failure(
                  [](auto store, auto validator)
                  {
                      EXPECT_CALL(*store, readInternalDoc(POLICY_NAME))
                          .WillOnce(::testing::Return(storeReadDocResp(POLICY_DOC)));
                      expectNsPolicy(store);
                      EXPECT_CALL(*validator, validatePolicy(EqualsJson(POLICY_DOC_2)))
                          .WillOnce(::testing::Return(validateOk()));
                      EXPECT_CALL(*store, upsertInternalDoc(POLICY_NAME_2, EqualsJson(POLICY_DOC_2)))
                          .WillOnce(::testing::Return(storeError()));
                  })),
        // Success
        CopyT(POLICY_NAME,
              POLICY_NAME_2,
              success(
                  [](auto store, auto validator)
                  {
                      EXPECT_CALL(*store, readInternalDoc(POLICY_NAME))
                          .WillOnce(::testing::Return(storeReadDocResp(POLICY_DOC)));
                      expectNsPolicy(store);
                      EXPECT_CALL(*validator, validatePolicy(POLICY_DOC_2)).WillOnce(::testing::Return(validateOk()));
                      EXPECT_CALL(*store, upsertInternalDoc(POLICY_NAME_2, EqualsJson(POLICY_DOC_2)))
                          .WillOnce(::testing::Return(storeOk()));
                  }))));

/*******************************************************************************
 * Clean deleted assets from policy
 ******************************************************************************/
using CleanDeletedT = std::tuple<base::Name, ExpectedFn<>>;
using CleanDeleted = PolicyTest<CleanDeletedT>;

TEST_P(CleanDeleted, Clean)
{
    auto [policy, expectedFn] = GetParam();

    auto expected = expectedFn(m_store, m_validator);
    auto res = m_policyManager->cleanDeleted(policy);
    if (base::isError(expected))
    {
        ASSERT_TRUE(base::isError(res));
    }
    else
    {
        ASSERT_FALSE(base::isError(res)) << "Error: " << base::getError(res).message << std::endl;
    }
}

INSTANTIATE_TEST_SUITE_P(
    PolicyTest,
    CleanDeleted,
    testing::Values(
        // Use cases
        CleanDeletedT("invalid_name", failure()),
        CleanDeletedT(POLICY_NAME,
                      failure(
                          [](auto store, auto) {
                              EXPECT_CALL(*store, readInternalDoc(POLICY_NAME))
                                  .WillOnce(::testing::Return(storeReadError<store::Doc>()));
                          })),
        CleanDeletedT(POLICY_NAME,
                      success(
                          [](auto store, auto validator)
                          {
                              EXPECT_CALL(*store, readInternalDoc(POLICY_NAME))
                                  .WillOnce(::testing::Return(storeReadDocResp(POLICY_DOC)));
                              EXPECT_CALL(*store, getNamespace({"decoder/system/0"}))
                                  .WillRepeatedly(testing::Return(storeGetNamespaceResp("system")));
                              EXPECT_CALL(*store, getNamespace({"decoder/wazuh/0"}))
                                  .WillRepeatedly(testing::Return(storeGetNamespaceError()));
                              EXPECT_CALL(*store, getNamespace({"decoder/user/0"}))
                                  .WillRepeatedly(testing::Return(storeGetNamespaceResp("user")));
                              EXPECT_CALL(*validator, validatePolicy(testing::_))
                                  .WillOnce(::testing::Return(validateOk()));
                              EXPECT_CALL(*store, upsertInternalDoc(POLICY_NAME, testing::_))
                                  .WillOnce(::testing::Return(storeOk()));
                          })),
        CleanDeletedT(POLICY_NAME,
                      success(
                          [](auto store, auto validator)
                          {
                              EXPECT_CALL(*store, readInternalDoc(POLICY_NAME))
                                  .WillOnce(::testing::Return(storeReadDocResp(POLICY_DOC)));
                              EXPECT_CALL(*store, getNamespace({"decoder/system/0"}))
                                  .WillRepeatedly(testing::Return(storeGetNamespaceResp("system")));
                              EXPECT_CALL(*store, getNamespace({"decoder/wazuh/0"}))
                                  .WillRepeatedly(testing::Return(storeGetNamespaceError()));
                              EXPECT_CALL(*store, getNamespace({"decoder/user/0"}))
                                  .WillRepeatedly(testing::Return(storeGetNamespaceResp("user")));
                              EXPECT_CALL(*validator, validatePolicy(testing::_))
                                  .WillOnce(::testing::Return(validateError()));
                              EXPECT_CALL(*store, upsertInternalDoc(POLICY_NAME, testing::_))
                                  .WillOnce(::testing::Return(storeOk()));
                          })),
        CleanDeletedT(POLICY_NAME,
                      failure(
                          [](auto store, auto validator)
                          {
                              EXPECT_CALL(*store, readInternalDoc(POLICY_NAME))
                                  .WillOnce(::testing::Return(storeReadDocResp(POLICY_DOC)));
                              EXPECT_CALL(*store, getNamespace({"decoder/system/0"}))
                                  .WillRepeatedly(testing::Return(storeGetNamespaceResp("system")));
                              EXPECT_CALL(*store, getNamespace({"decoder/wazuh/0"}))
                                  .WillRepeatedly(testing::Return(storeGetNamespaceError()));
                              EXPECT_CALL(*store, getNamespace({"decoder/user/0"}))
                                  .WillRepeatedly(testing::Return(storeGetNamespaceResp("user")));
                              EXPECT_CALL(*validator, validatePolicy(testing::_))
                                  .WillOnce(::testing::Return(validateError()));
                              EXPECT_CALL(*store, upsertInternalDoc(POLICY_NAME, testing::_))
                                  .WillOnce(::testing::Return(storeError()));
                          })),
        CleanDeletedT(POLICY_NAME,
                      failure(
                          [](auto store, auto validator)
                          {
                              EXPECT_CALL(*store, readInternalDoc(POLICY_NAME))
                                  .WillOnce(::testing::Return(storeReadDocResp(POLICY_DOC)));
                              expectNsPolicy(store);
                          }))));
