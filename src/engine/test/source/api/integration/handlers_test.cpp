#include "catalogTestShared.hpp"

#include <api/integration/handlers.hpp>
#include <gtest/gtest.h>

const std::string rCommand {"dummy cmd"};
const std::string rOrigin {"Dummy org module"};

TEST(Handlers, policyAddIntegration)
{
    auto integration = std::make_shared<api::integration::Integration>(getIntegration());

    api::Handler cmd;
    ASSERT_NO_THROW(cmd = api::integration::handlers::integrationAddTo(integration));
    json::Json params;
    params.setObject();
    params.setString(policyResource.m_name.fullName(), "/policy");
    params.setString(integrationResource.m_name.fullName(), "/integration");
    ASSERT_NO_THROW(cmd(api::wpRequest::create(rCommand, rOrigin, params)));
    auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));
    const auto expectedData = json::Json(R"({"status":"OK"})");

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Expected: " << expectedData.prettyStr() << std::endl
                                             << "Actual: " << response.data().prettyStr() << std::endl;
}

TEST(Handlers, policyAddIntegration_MissingPolicy)
{
    auto integration = std::make_shared<api::integration::Integration>(getIntegration());

    api::Handler cmd;
    ASSERT_NO_THROW(cmd = api::integration::handlers::integrationAddTo(integration));
    json::Json params;
    params.setObject();
    params.setString(integrationResource.m_name.fullName(), "/integration");
    ASSERT_NO_THROW(cmd(api::wpRequest::create(rCommand, rOrigin, params)));
    auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));
    const auto expectedData = json::Json(R"({"status":"ERROR","error":"Missing /policy parameter"})");

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Expected: " << expectedData.prettyStr() << std::endl
                                             << "Actual: " << response.data().prettyStr() << std::endl;
}

TEST(Handlers, policyAddIntegration_MissingIntegration)
{
    auto integration = std::make_shared<api::integration::Integration>(getIntegration());

    api::Handler cmd;
    ASSERT_NO_THROW(cmd = api::integration::handlers::integrationAddTo(integration));
    json::Json params;
    params.setObject();
    params.setString(policyResource.m_name.fullName(), "/policy");
    ASSERT_NO_THROW(cmd(api::wpRequest::create(rCommand, rOrigin, params)));
    auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));
    const auto expectedData = json::Json(R"({"status":"ERROR","error":"Missing /integration parameter"})");

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Expected: " << expectedData.prettyStr() << std::endl
                                             << "Actual: " << response.data().prettyStr() << std::endl;
}

TEST(Handlers, policyAddIntegration_IncorrectPolicyName)
{
    auto integration = std::make_shared<api::integration::Integration>(getIntegration());

    api::Handler cmd;
    ASSERT_NO_THROW(cmd = api::integration::handlers::integrationAddTo(integration));
    json::Json params;
    params.setObject();
    params.setString("integration/name/ok", "/policy");
    params.setString(integrationResource.m_name.fullName(), "/integration");
    ASSERT_NO_THROW(cmd(api::wpRequest::create(rCommand, rOrigin, params)));
    auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));
    const auto expectedData = json::Json(
        R"({"status":"ERROR","error":"Expected policy resource type, got 'integration' for resource 'integration/name/ok'"})");

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Expected: " << expectedData.prettyStr() << std::endl
                                             << "Actual: " << response.data().prettyStr() << std::endl;
}

TEST(Handlers, policyAddIntegration_IncorrectIntegrationName)
{
    auto integration = std::make_shared<api::integration::Integration>(getIntegration());

    api::Handler cmd;
    ASSERT_NO_THROW(cmd = api::integration::handlers::integrationAddTo(integration));
    json::Json params;
    params.setObject();
    params.setString(policyResource.m_name.fullName(), "/policy");
    params.setString("policy/name/ok", "/integration");
    ASSERT_NO_THROW(cmd(api::wpRequest::create(rCommand, rOrigin, params)));
    auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));
    const auto expectedData = json::Json(
        R"({"status":"ERROR","error":"Expected integration resource type, got 'policy' for resource 'policy/name/ok'"})");

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Expected: " << expectedData.prettyStr() << std::endl
                                             << "Actual: " << response.data().prettyStr() << std::endl;
}

TEST(Handlers, integrationRemoveFrom)
{
    auto integration = std::make_shared<api::integration::Integration>(getIntegration());

    api::Handler cmd;
    ASSERT_NO_THROW(cmd = api::integration::handlers::integrationRemoveFrom(integration));
    json::Json params;
    params.setObject();
    params.setString(policyResource.m_name.fullName(), "/policy");
    params.setString(integrationResource.m_name.fullName(), "/integration");
    ASSERT_NO_THROW(cmd(api::wpRequest::create(rCommand, rOrigin, params)));
    auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));
    const auto expectedData = json::Json(R"({"status":"OK"})");

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Expected: " << expectedData.prettyStr() << std::endl
                                             << "Actual: " << response.data().prettyStr() << std::endl;
}

TEST(Handlers, registerHandlers)
{
    auto integration = std::make_shared<api::integration::Integration>(getIntegration());
    auto api = std::make_shared<api::Api>();

    ASSERT_NO_THROW(api::integration::handlers::registerHandlers(integration, api));
}
