#include "catalogTestShared.hpp"

#include <api/integration/handlers.hpp>
#include <gtest/gtest.h>

#include "../../apiAuxiliarFunctions.hpp"

const std::string rCommand {"dummy cmd"};
const std::string rOrigin {"Dummy org module"};
constexpr auto POLICY_NOT_FOUND {2};
constexpr auto INTEGRATION_NOT_FOUND {3};

// TODO: Create catalog interface to mock and classify this test suite as unitary.
class IntegrationAddApiTest : public ::testing::TestWithParam<std::tuple<int, std::string, std::string, std::string>>
{
protected:
    void SetUp() override
    {
        initLogging();
        m_spIntegration = std::make_shared<api::integration::Integration>(getIntegration());
    }
    std::shared_ptr<api::integration::Integration> m_spIntegration;
};

TEST_P(IntegrationAddApiTest, IntegrationAdd)
{
    auto [execution, policy, integration, output] = GetParam();

    api::Handler cmd;
    ASSERT_NO_THROW(cmd = api::integration::handlers::integrationAddTo(m_spIntegration));
    json::Json params;
    params.setObject();

    if (POLICY_NOT_FOUND == execution)
    {
        params.setString(integration, "/integration");
    }
    else if (INTEGRATION_NOT_FOUND == execution)
    {
        params.setString(policy, "/policy");
    }
    else
    {
        params.setString(policy, "/policy");
        params.setString(integration, "/integration");
    }

    ASSERT_NO_THROW(cmd(api::wpRequest::create(rCommand, rOrigin, params)));
    auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));
    const auto expectedData = json::Json(output.c_str());

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Expected: " << expectedData.prettyStr() << std::endl
                                             << "Actual: " << response.data().prettyStr() << std::endl;
}

INSTANTIATE_TEST_SUITE_P(
    IntegrationAdd,
    IntegrationAddApiTest,
    ::testing::Values(
        std::make_tuple(
            1, policyResource.m_name.fullName(), integrationResource.m_name.fullName(), R"({"status":"OK"})"),
        std::make_tuple(
            2, "", integrationResource.m_name.fullName(), R"({"status":"ERROR","error":"Missing /policy parameter"})"),
        std::make_tuple(
            3, policyResource.m_name.fullName(), "", R"({"status":"ERROR","error":"Missing /integration parameter"})"),
        std::make_tuple(
            4,
            "integration/name/ok",
            integrationResource.m_name.fullName(),
            R"({"status":"ERROR","error":"Expected policy resource type, got 'integration' for resource 'integration/name/ok'"})"),
        std::make_tuple(
            5,
            policyResource.m_name.fullName(),
            "policy/name/ok",
            R"({"status":"ERROR","error":"Expected integration resource type, got 'policy' for resource 'policy/name/ok'"})")));

class IntegrationRemoveApiTest : public ::testing::TestWithParam<std::tuple<int, std::string, std::string, std::string>>
{
protected:
    void SetUp() override
    {
        initLogging();
        m_spIntegration = std::make_shared<api::integration::Integration>(getIntegration());
    }
    std::shared_ptr<api::integration::Integration> m_spIntegration;
};

TEST_P(IntegrationRemoveApiTest, IntegrationRemove)
{
    auto [execution, policy, integration, output] = GetParam();

    api::Handler cmd;
    ASSERT_NO_THROW(cmd = api::integration::handlers::integrationRemoveFrom(m_spIntegration));
    json::Json params;
    params.setObject();

    if (POLICY_NOT_FOUND == execution)
    {
        params.setString(integration, "/integration");
    }
    else if (INTEGRATION_NOT_FOUND == execution)
    {
        params.setString(policy, "/policy");
    }
    else
    {
        params.setString(policy, "/policy");
        params.setString(integration, "/integration");
    }

    ASSERT_NO_THROW(cmd(api::wpRequest::create(rCommand, rOrigin, params)));
    auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));
    const auto expectedData = json::Json(output.c_str());

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Expected: " << expectedData.prettyStr() << std::endl
                                             << "Actual: " << response.data().prettyStr() << std::endl;
}

INSTANTIATE_TEST_SUITE_P(
    IntegrationRemove,
    IntegrationRemoveApiTest,
    ::testing::Values(
        std::make_tuple(
            1, policyResource.m_name.fullName(), integrationResource.m_name.fullName(), R"({"status":"OK"})"),
        std::make_tuple(
            2, "", integrationResource.m_name.fullName(), R"({"status":"ERROR","error":"Missing /policy parameter"})"),
        std::make_tuple(
            3, policyResource.m_name.fullName(), "", R"({"status":"ERROR","error":"Missing /integration parameter"})"),
        std::make_tuple(
            4,
            "integration/name/ok",
            integrationResource.m_name.fullName(),
            R"({"status":"ERROR","error":"Expected policy resource type, got 'integration' for resource 'integration/name/ok'"})"),
        std::make_tuple(
            5,
            policyResource.m_name.fullName(),
            "policy/name/ok",
            R"({"status":"ERROR","error":"Expected integration resource type, got 'policy' for resource 'policy/name/ok'"})")));
