#include <gtest/gtest.h>

#include <memory>

#include <api/catalog/catalog.hpp>
#include <api/integration/integration.hpp>
#include <testsCommon.hpp>

#include "catalogTestShared.hpp"

class IntegrationTest : public testing::Test {
protected:

    void SetUp() override {
        initLogging();
    }
};

TEST_F(IntegrationTest, AddIntegrationPolicyNoIntegrations)
{
    auto integration = getIntegration();
    std::optional<base::Error> error;
    ASSERT_NO_THROW(error = integration.addTo(policyNoIntegrations, integrationResource));
    ASSERT_FALSE(error);
}

TEST_F(IntegrationTest, AddIntegrationPolicy)
{
    auto integration = getIntegration();
    std::optional<base::Error> error;
    ASSERT_NO_THROW(error = integration.addTo(policyResource, integrationResource));
    ASSERT_FALSE(error);
}

TEST_F(IntegrationTest, AddIntegrationPolicyDuplicated)
{
    auto integration = getIntegration();
    std::optional<base::Error> error;
    ASSERT_NO_THROW(error = integration.addTo(policyDuplicated, integrationResource));
    ASSERT_TRUE(error);
}

TEST_F(IntegrationTest, RemoveIntegrationPolicy)
{
    auto integration = getIntegration();
    std::optional<base::Error> error;
    ASSERT_NO_THROW(error = integration.removeFrom(policyDuplicated, integrationResource));
    ASSERT_FALSE(error);
    ASSERT_NO_THROW(error = integration.removeFrom(policyResource, integrationResource));
    ASSERT_FALSE(error);
}

TEST_F(IntegrationTest, RemoveIntegrationPolicyNoIntegrations)
{
    auto integration = getIntegration();
    std::optional<base::Error> error;
    ASSERT_NO_THROW(error = integration.removeFrom(policyNoIntegrations, integrationResource));
    ASSERT_FALSE(error);
}
