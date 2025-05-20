#include <gtest/gtest.h>

#include <base/logging.hpp>
#include <rbac/rbac.hpp>
#include <store/mockStore.hpp>

using namespace rbac;
using namespace store::mocks;

auto constexpr OK_ROLE = "role";
auto constexpr OK_RESOURCE = Resource::ASSET;
auto constexpr OK_OPERATION = Operation::READ;

auto constexpr BAD_ROLE = "bad_role";
auto constexpr BAD_RESOURCE = Resource::SYSTEM_ASSET;
auto constexpr BAD_OPERATION = Operation::WRITE;

auto MODEL_JSON = json::Json {R"({
    "role": [
        {
            "resource": "asset",
            "operation": "read"
        }
    ],
    "role2": [
        {
            "resource": "asset",
            "operation": "read"
        },
        {
            "resource": "asset",
            "operation": "write"
        }
    ],
    "role3": [
        {
            "resource": "system_asset",
            "operation": "read"
        },
        {
            "resource": "system_asset",
            "operation": "write"
        },
        {
            "resource": "asset",
            "operation": "read"
        },
        {
            "resource": "asset",
            "operation": "write"
        }
    ]
})"};
auto MODEL_ERROR_JSON = json::Json {"{}"};

/******************************************************************************/
/* General tests */
/******************************************************************************/
class RBACTest : public ::testing::Test
{
protected:
    std::shared_ptr<MockStoreInternal> mockStore;

    void SetUp() override
    {
        logging::testInit();
        mockStore = std::make_shared<MockStoreInternal>();
    }

    void TearDown() override {}
};

TEST_F(RBACTest, InitDefault)
{
    EXPECT_CALL(*mockStore, readInternalDoc(testing::Eq(base::Name {detail::MODEL_NAME})))
        .WillOnce(::testing::Return(storeReadError<store::Doc>()));
    // EXPECT_CALL(*mockStore, updateInternalDoc(testing::Eq(base::Name {detail::MODEL_NAME}), testing::_))
    //     .WillOnce(::testing::Return(storeOk()));

    std::shared_ptr<RBAC> rbac;
    ASSERT_NO_THROW(rbac = std::make_shared<RBAC>(mockStore));
}

TEST_F(RBACTest, InitLoadModel)
{
    EXPECT_CALL(*mockStore, readInternalDoc(testing::Eq(base::Name {detail::MODEL_NAME})))
        .WillOnce(::testing::Return(storeReadDocResp(MODEL_JSON)));

    std::shared_ptr<RBAC> rbac;
    ASSERT_NO_THROW(rbac = std::make_shared<RBAC>(mockStore));
}

TEST_F(RBACTest, InitLoadModelError)
{
    EXPECT_CALL(*mockStore, readInternalDoc(testing::Eq(base::Name {detail::MODEL_NAME})))
        .WillOnce(::testing::Return(storeReadDocResp(MODEL_ERROR_JSON)));
    EXPECT_CALL(*mockStore, upsertInternalDoc(testing::Eq(base::Name {detail::MODEL_NAME}), testing::_))
        .WillOnce(::testing::Return(storeOk()));

    std::shared_ptr<RBAC> rbac;
    ASSERT_NO_THROW(rbac = std::make_shared<RBAC>(mockStore));
}

TEST_F(RBACTest, InitSaveError)
{
    EXPECT_CALL(*mockStore, readInternalDoc(testing::Eq(base::Name {detail::MODEL_NAME})))
        .WillOnce(::testing::Return(storeReadError<store::Doc>()));
    EXPECT_CALL(*mockStore, upsertInternalDoc(testing::Eq(base::Name {detail::MODEL_NAME}), testing::_))
        .WillOnce(::testing::Return(storeError()));

    std::shared_ptr<RBAC> rbac;
    ASSERT_NO_THROW(rbac = std::make_shared<RBAC>(mockStore));
}

TEST_F(RBACTest, Shutdown)
{
    EXPECT_CALL(*mockStore, readInternalDoc(testing::Eq(base::Name {detail::MODEL_NAME})))
        .WillOnce(::testing::Return(storeReadDocResp(MODEL_JSON)));
    EXPECT_CALL(*mockStore, upsertInternalDoc(testing::Eq(base::Name {detail::MODEL_NAME}), testing::Eq(MODEL_JSON)))
        .WillOnce(::testing::Return(storeOk()));

    std::shared_ptr<RBAC> rbac;
    ASSERT_NO_THROW(rbac = std::make_shared<RBAC>(mockStore));

    ASSERT_NO_THROW(rbac->shutdown());
}

TEST_F(RBACTest, ShutdownError)
{
    EXPECT_CALL(*mockStore, readInternalDoc(testing::Eq(base::Name {detail::MODEL_NAME})))
        .WillOnce(::testing::Return(storeReadDocResp(MODEL_JSON)));
    EXPECT_CALL(*mockStore, upsertInternalDoc(testing::Eq(base::Name {detail::MODEL_NAME}), testing::Eq(MODEL_JSON)))
        .WillOnce(::testing::Return(storeError()));

    std::shared_ptr<RBAC> rbac;
    ASSERT_NO_THROW(rbac = std::make_shared<RBAC>(mockStore));

    ASSERT_NO_THROW(rbac->shutdown());
}

/******************************************************************************/
/* Authentication tests */
/******************************************************************************/
using AuthInput = std::tuple<bool, std::string, Resource, Operation>;
class AuthTest : public ::testing::TestWithParam<AuthInput>
{
protected:
    std::shared_ptr<MockStoreInternal> mockStore;
    std::shared_ptr<IRBAC> rbac;

    void SetUp() override
    {
        logging::testInit();
        mockStore = std::make_shared<MockStoreInternal>();
        EXPECT_CALL(*mockStore, readInternalDoc(testing::Eq(base::Name {detail::MODEL_NAME})))
            .WillOnce(::testing::Return(storeReadDocResp(MODEL_JSON)));
        rbac = std::make_shared<RBAC>(mockStore);
    }

    void TearDown() override {}
};

TEST_P(AuthTest, AuthFn)
{
    auto [shouldPass, requestRole, resource, operation] = GetParam();

    RBAC::AuthFn authFn;
    ASSERT_NO_THROW(authFn = rbac->getAuthFn(resource, operation));

    if (shouldPass)
    {
        EXPECT_TRUE(authFn(requestRole));
    }
    else
    {
        EXPECT_FALSE(authFn(requestRole));
    }
}

INSTANTIATE_TEST_SUITE_P(RBAC,
                         AuthTest,
                         ::testing::Values(AuthInput {true, OK_ROLE, OK_RESOURCE, OK_OPERATION},
                                           AuthInput {false, BAD_ROLE, OK_RESOURCE, OK_OPERATION},
                                           AuthInput {false, OK_ROLE, BAD_RESOURCE, OK_OPERATION},
                                           AuthInput {false, OK_ROLE, OK_RESOURCE, BAD_OPERATION},
                                           AuthInput {false, BAD_ROLE, BAD_RESOURCE, OK_OPERATION},
                                           AuthInput {false, BAD_ROLE, OK_RESOURCE, BAD_OPERATION},
                                           AuthInput {false, OK_ROLE, BAD_RESOURCE, BAD_OPERATION},
                                           AuthInput {false, BAD_ROLE, BAD_RESOURCE, BAD_OPERATION}));
