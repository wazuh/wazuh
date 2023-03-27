#include <gtest/gtest.h>

#include <memory>

#include <api/catalog/catalog.hpp>
#include <api/integration/integration.hpp>

#include "catalogTestShared.hpp"

TEST(IntegrationTest, AddIntegrationPolicyNoIntegrations)
{
    auto integration = getIntegration();
    std::optional<base::Error> error;
    ASSERT_NO_THROW(error = integration.addTo(policyNoIntegrations, integrationResource));
    ASSERT_FALSE(error);
}

TEST(IntegrationTest, AddIntegrationPolicy)
{
    auto integration = getIntegration();
    std::optional<base::Error> error;
    ASSERT_NO_THROW(error = integration.addTo(policyResource, integrationResource));
    ASSERT_FALSE(error);
}

TEST(IntegrationTest, AddIntegrationPolicyDuplicated)
{
    auto integration = getIntegration();
    std::optional<base::Error> error;
    ASSERT_NO_THROW(error = integration.addTo(policyDuplicated, integrationResource));
    ASSERT_TRUE(error);
}

TEST(IntegrationTest, RemoveIntegrationPolicy)
{
    auto integration = getIntegration();
    std::optional<base::Error> error;
    ASSERT_NO_THROW(error = integration.removeFrom(policyDuplicated, integrationResource));
    ASSERT_FALSE(error);
    ASSERT_NO_THROW(error = integration.removeFrom(policyResource, integrationResource));
    ASSERT_FALSE(error);
}

TEST(IntegrationTest, RemoveIntegrationPolicyNoIntegrations)
{
    auto integration = getIntegration();
    std::optional<base::Error> error;
    ASSERT_NO_THROW(error = integration.removeFrom(policyNoIntegrations, integrationResource));
    ASSERT_FALSE(error);
}
