#include <gtest/gtest.h>

#include <memory>

#include <api/catalog/catalog.hpp>
#include <api/integration/integration.hpp>

#include "../../apiAuxiliarFunctions.hpp"
#include "catalogTestShared.hpp"

// TODO: Create catalog interface to mock and classify this test suite as unitary.
class IntegrationTest : public ::testing::TestWithParam<std::tuple<int, api::catalog::Resource, api::catalog::Resource>>
{
protected:
    void SetUp() override { initLogging(); }
};

TEST_P(IntegrationTest, AddAndRemoveIntegration)
{
    auto [execution, policy, integrations] = GetParam();
    auto integration = getIntegration();
    std::optional<base::Error> error;
    if (execution < 3)
    {
        ASSERT_NO_THROW(error = integration.addTo(policy, integrations));
        if (policy.m_name == policyDuplicated.m_name)
        {
            ASSERT_TRUE(error);
        }
        else
        {
            ASSERT_FALSE(error);
        }
    }
    else
    {
        ASSERT_NO_THROW(error = integration.removeFrom(policy, integrations));
        ASSERT_FALSE(error);
    }
}

INSTANTIATE_TEST_SUITE_P(AddAndRemoveIntegration,
                         IntegrationTest,
                         ::testing::Values(std::make_tuple(1, policyNoIntegrations, integrationResource),
                                           std::make_tuple(2, policyResource, integrationResource),
                                           std::make_tuple(3, policyDuplicated, integrationResource),
                                           std::make_tuple(4, policyDuplicated, integrationResource),
                                           std::make_tuple(5, policyResource, integrationResource),
                                           std::make_tuple(5, policyNoIntegrations, integrationResource)));
