#include <gtest/gtest.h>

#include <store/mockStore.hpp>
#include <builder/mockValidator.hpp>

#include <policy/policy.hpp>


template <typename T = std::string>
class PolicyTest : public ::testing::TestWithParam<T>
{
  public:
    using ParamType = T;  // <-- Añade esto
  protected:
    std::shared_ptr<store::mocks::MockStore> m_store;
    std::shared_ptr<builder::mocks::MockValidator> m_validator;
    std::unique_ptr<api::policy::Policy> m_policyManager;

    void SetUp() override
    {
        m_store = std::make_shared<store::mocks::MockStore>();
        m_validator = std::make_shared<builder::mocks::MockValidator>();
        m_policyManager = std::make_unique<api::policy::Policy>(m_store, m_validator);
    }

    void TearDown() override
    {
        m_store.reset();
        m_validator.reset();
    }
};

/**************************************************************
 *                Test create policy
 *************************************************************/
// Fail name
class PolicyCreateTest : public PolicyTest<std::string>
{
};

TEST_P(PolicyCreateTest, InvalidName)
{
    auto policyStr = GetParam();
    // Verify arguments
    base::Name policyName;

    try {
        policyName = base::Name(policyStr);
    } catch (const std::exception& e) {
        FAIL() << "Failed to create policy name from string: " << policyStr << ", error: " << e.what();
    }

    auto res = m_policyManager->create(policyName);
    ASSERT_TRUE(base::isError(res));

}

INSTANTIATE_TEST_SUITE_P(PolicyCreateFailTest,
                         PolicyCreateTest,
                         ::testing::Values("invalidName",
                                           "pol/icy",
                                           "policy/noVersion",
                                           "policy/name/version/extraPart",
                                           "\n",
                                           "poLICY/name/version"));

// Policy already exists
TEST_F(PolicyCreateTest, PolicyCreateFailAlreadyExists)
{
    auto policyName = base::Name("policy/name/version");
    EXPECT_CALL(*m_store, existsInternalDoc(policyName)).WillOnce(::testing::Return(true));

    auto res = m_policyManager->create(policyName);
    ASSERT_TRUE(base::isError(res));
}

// Fail to validate policy
TEST_F(PolicyCreateTest, PolicyCreateFailValidate)
{
    auto policyName = base::Name("policy/name/version");

    EXPECT_CALL(*m_store, existsInternalDoc(policyName)).WillOnce(::testing::Return(false));
    EXPECT_CALL(*m_validator, validatePolicy(testing::_)).WillOnce(::testing::Return(builder::mocks::validateError()));

    auto res = m_policyManager->create(policyName);
    ASSERT_TRUE(base::isError(res));
}

// Fail to upsert policy
TEST_F(PolicyCreateTest, PolicyCreateFailUpsert)
{
    auto policyName = base::Name("policy/name/version");

    EXPECT_CALL(*m_store, existsInternalDoc(policyName)).WillOnce(::testing::Return(false));
    EXPECT_CALL(*m_validator, validatePolicy(testing::_)).WillOnce(::testing::Return(std::nullopt));
    EXPECT_CALL(*m_store, upsertInternalDoc(policyName, testing::_)) // TODO Shuold check doc? Or is UT enough?
        .WillOnce(::testing::Return(store::mocks::storeError()));

    auto res = m_policyManager->create(policyName);
    ASSERT_TRUE(base::isError(res));
}


// Success
TEST_F(PolicyCreateTest, PolicyCreateSuccess)
{
    auto policyName = base::Name("policy/name/version");

    EXPECT_CALL(*m_store, existsInternalDoc(policyName)).WillOnce(::testing::Return(false));
    EXPECT_CALL(*m_validator, validatePolicy(testing::_)).WillOnce(::testing::Return(std::nullopt));
    EXPECT_CALL(*m_store, upsertInternalDoc(policyName, testing::_)) // TODO Shuold check doc? Or is UT enough?
        .WillOnce(::testing::Return(std::nullopt));

    ASSERT_FALSE(m_policyManager->create(policyName));
}

/**************************************************************
 *                Test delete policy
 *************************************************************/
// Fail name
class PolicyDeleteTest : public PolicyTest<std::string>
{
};

TEST_P(PolicyDeleteTest, InvalidName)
{
    auto policyStr = GetParam();
    // Verify arguments
    base::Name policyName;

    try {
        policyName = base::Name(policyStr);
    } catch (const std::exception& e) {
        FAIL() << "Failed to create policy name from string: " << policyStr << ", error: " << e.what();
    }

    auto res = m_policyManager->del(policyName);
    ASSERT_TRUE(base::isError(res));

}

INSTANTIATE_TEST_SUITE_P(PolicyDeleteFailTest,
                         PolicyDeleteTest,
                         ::testing::Values("invalidName",
                                           "pol/icy",
                                           "policy/noVersion",
                                           "policy/name/version/extraPart",
                                           "\n",
                                           "poLICY/name/version"));

// Policy does not exist
TEST_F(PolicyDeleteTest, PolicyDeleteFailDoesNotExist)
{
    auto policyName = base::Name("policy/name/version");
    EXPECT_CALL(*m_store, deleteInternalDoc(policyName)).WillOnce(::testing::Return(store::mocks::storeError()));

    auto res = m_policyManager->del(policyName);
    ASSERT_TRUE(base::isError(res));
}

// Success
TEST_F(PolicyDeleteTest, PolicyDeleteSuccess)
{
    auto policyName = base::Name("policy/name/version");

    EXPECT_CALL(*m_store, deleteInternalDoc(policyName)).WillOnce(::testing::Return(std::nullopt));
    ASSERT_FALSE(m_policyManager->del(policyName));
}

/**************************************************************
 *                Test get policy
 *************************************************************/
// Fail name
class PolicyGetTest : public PolicyTest<std::string>
{
};

TEST_P(PolicyGetTest, InvalidName)
{
    auto policyStr = GetParam();
    // Verify arguments
    base::Name policyName;

    try {
        policyName = base::Name(policyStr);
    } catch (const std::exception& e) {
        FAIL() << "Failed to create policy name from string: " << policyStr << ", error: " << e.what();
    }

    auto res = m_policyManager->get(policyName, {});
    ASSERT_TRUE(base::isError(res));

}

INSTANTIATE_TEST_SUITE_P(PolicyGetFailTest,
                         PolicyGetTest,
                         ::testing::Values("invalidName",
                                           "pol/icy",
                                           "policy/noVersion",
                                           "policy/name/version/extraPart",
                                           "\n",
                                           "poLICY/name/version"));

// Policy does not exist
TEST_F(PolicyGetTest, PolicyGetFailDoesNotExist)
{
    auto policyName = base::Name("policy/name/version");
    EXPECT_CALL(*m_store, readInternalDoc(policyName)).WillOnce(::testing::Return(store::mocks::storeReadError<store::Doc>()));

    auto res = m_policyManager->get(policyName, {});
    ASSERT_TRUE(base::isError(res));
}

// Success

class PolicyGetOkTest : public PolicyTest<std::tuple<std::string, json::Json>>
{
};

TEST_P(PolicyGetOkTest, PolicyGetSuccess)
{
    GTEST_SKIP();
    auto [expYML, policyJson] = GetParam();
    // Verify arguments
    base::Name policyName {"policy/validname/1"};

    EXPECT_CALL(*m_store, readInternalDoc(policyName)).WillOnce(::testing::Return(store::mocks::storeReadDocResp(policyJson)));

    auto res = m_policyManager->get(policyName, {});
    ASSERT_FALSE(base::isError(res));
    //ASSERT_EQ(res.value(), policyJson.dump());
}

INSTANTIATE_TEST_SUITE_P(PolicyGetSuccessTest,
                         PolicyGetOkTest,
                         ::testing::Values(std::make_tuple("policy: policy/test/0\nhash: 4112711263806056918\nassets: \n  - integration/wazuh-core/0\n  - integration/syslog/0\n  - integration/system/0\n  - integration/windows/0\n  - integration/apache-http/0\ndefault_parents: \n  - wazuh: decoder/integrations/0\n", json::Json {R"({"name":"policy/test/0","hash":"4112711263806056918","assets":["integration/wazuh-core/0","integration/syslog/0","integration/system/0","integration/windows/0","integration/apache-http/0"],"default_parents":{"wazuh":"decoder/integrations/0"}})"})));
