#include <api/catalog/handlers.hpp>
#include <gtest/gtest.h>

#include "catalogTestShared.hpp"

const std::string rCommand {"dummy cmd"};
const std::string rOrigin {"Dummy org module"};
base::Name name(api::catalog::Resource::typeToStr(api::catalog::Resource::Type::decoder));
base::Name completeName({api::catalog::Resource::typeToStr(api::catalog::Resource::Type::decoder),
                         successName.parts()[1],
                         successName.parts()[2]});
constexpr auto CONTENT_NOT_FOUND {6};
constexpr auto NAME_OR_TYPE_NOT_FOUND {4};
constexpr auto FORMAT_NOT_FOUND {5};

class CatalogGetApiTest : public ::testing::TestWithParam<std::tuple<std::string, std::string>>
{
protected:
    void SetUp() override
    {
        logging::testInit();
        m_spCatalog = std::make_shared<api::catalog::Catalog>(getConfig());
    }
    std::shared_ptr<api::catalog::Catalog> m_spCatalog;
};

TEST_P(CatalogGetApiTest, ResourseGet)
{
    auto [input, output] = GetParam();
    api::HandlerSync cmd;
    auto mockRbac = std::make_shared<rbac::mocks::MockRBAC>();
    ASSERT_NO_THROW(cmd = api::catalog::handlers::resourceGet(m_spCatalog, mockRbac));
    json::Json params {input.c_str()};

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
    ResourseGet,
    CatalogGetApiTest,
    ::testing::Values(
        std::make_tuple(R"({"name": "decoder/name/ok", "format": "json", "namespaceid": "ignored"})",
            R"({
                "status": "ERROR",
                "error": "Could not get resource 'decoder/name/ok': Resource 'decoder/name/ok' does not have an associated namespace"
            })"),
        std::make_tuple(R"({"name": "decoder/name/ok", "format": "json", "namespaceid": "ignored"})",
            R"({
                "status": "ERROR",
                "error": "Could not get resource 'decoder/name/ok': Resource 'decoder/name/ok' does not have an associated namespace"
            })"),
        std::make_tuple(R"({"name": "decoder/name/ok"})",
                        R"({"status":"ERROR","error":"Missing or invalid /format parameter"})"),
        std::make_tuple(R"({"name": "decoder/name/ok", "format": "json"})",
                        R"({"status":"ERROR","error":"Missing /namespaceid parameter"})"),
        std::make_tuple(
            R"({"name": "decoder/name/fail", "format": "json", "namespaceid": "ignored"})",
            R"({
                "status": "ERROR",
                "error": "Could not get resource 'decoder/name/fail': Resource 'decoder/name/fail' does not have an associated namespace"
            })"),
        std::make_tuple(R"({"name": "decoder/name/fail", "format": "invalid"})",
                        R"({"status":"ERROR","error":"Missing or invalid /format parameter"})"),
        std::make_tuple(R"({"format": "json"})", R"({"status":"ERROR","error":"Missing /name parameter"})"),
        std::make_tuple(R"({"name": "invalid", "format": "json", "namespaceid": "ignored"})",
                        R"({"status":"ERROR","error":"Invalid collection type \"invalid\""})")));

class CatalogPostApiTest
    : public ::testing::TestWithParam<std::tuple<int, std::string, std::string, std::string, std::string>>
{
protected:
    void SetUp() override
    {
        logging::testInit();
        m_spCatalog = std::make_shared<api::catalog::Catalog>(getConfig());
    }
    std::shared_ptr<api::catalog::Catalog> m_spCatalog;
};

TEST_P(CatalogPostApiTest, ResoursePost)
{
    auto [execution, type, format, content, output] = GetParam();
    api::HandlerSync cmd;
    auto mockRbac = std::make_shared<rbac::mocks::MockRBAC>();
    ASSERT_NO_THROW(cmd = api::catalog::handlers::resourcePost(m_spCatalog, mockRbac));
    json::Json params;

    if (execution == NAME_OR_TYPE_NOT_FOUND)
    {
        params.setString(format, "/format");
        params.setString(content, "/content");
    }
    else if (execution == FORMAT_NOT_FOUND)
    {
        params.setString(type, "/type");
        params.setString(content, "/content");
    }
    else if (execution == CONTENT_NOT_FOUND)
    {
        params.setString(type, "/type");
        params.setString(format, "/format");
    }
    else
    {
        params.setString(format, "/format");
        params.setString(type, "/type");
        params.setString(content, "/content");
    }

    params.setString("ignored", "/namespaceid");

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
    ResoursePost,
    CatalogPostApiTest,
    ::testing::Values(
        std::make_tuple(1, name.fullName(), "json", successJson.str(), R"({"status":"OK"})"),
        std::make_tuple(2, name.fullName(), "json", successJson.str(), R"({"status":"OK"})"),
        std::make_tuple(3,
                        successName.fullName(),
                        "json",
                        successJson.str(),
                        R"({"status":"ERROR","error":"Missing /type parameter or is invalid"})"),
        std::make_tuple(
            4, "", "json", successJson.str(), R"({"status":"ERROR","error":"Missing /type parameter or is invalid"})"),
        std::make_tuple(5,
                        name.fullName(),
                        "",
                        successJson.str(),
                        R"({"status":"ERROR","error":"Missing /format parameter or is invalid"})"),
        std::make_tuple(6, name.fullName(), "json", "", R"({"status":"ERROR","error":"Missing /content parameter"})")));

class CatalogPutApiTest
    : public ::testing::TestWithParam<std::tuple<int, std::string, std::string, std::string, std::string>>
{
protected:
    void SetUp() override
    {
        logging::testInit();
        m_spCatalog = std::make_shared<api::catalog::Catalog>(getConfig());
    }
    std::shared_ptr<api::catalog::Catalog> m_spCatalog;
};

TEST_P(CatalogPutApiTest, ResoursePost)
{
    auto [execution, name, format, content, output] = GetParam();
    api::HandlerSync cmd;
    auto mockRbac = std::make_shared<rbac::mocks::MockRBAC>();
    ASSERT_NO_THROW(cmd = api::catalog::handlers::resourcePut(m_spCatalog, mockRbac));
    json::Json params;

    if (execution == NAME_OR_TYPE_NOT_FOUND)
    {
        params.setString(format, "/format");
        params.setString(content, "/content");
    }
    else if (execution == FORMAT_NOT_FOUND)
    {
        params.setString(name, "/name");
        params.setString(content, "/content");
    }
    else if (execution == CONTENT_NOT_FOUND)
    {
        params.setString(name, "/name");
        params.setString(format, "/format");
    }
    else
    {
        params.setString(format, "/format");
        params.setString(name, "/name");
        params.setString(content, "/content");
    }

    params.setString("ignored", "/namespaceid");

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
    ResoursePut,
    CatalogPutApiTest,
    ::testing::Values(
        std::make_tuple(1, completeName.fullName(), "json", successJson.str(), R"({
            "status": "ERROR",
            "error": "Could not update resource 'decoder/name/ok': Resource 'decoder/name/ok' does not have an associated namespace"
        })"),
        std::make_tuple(2, completeName.fullName(), "json", successJson.str(), R"({
            "status": "ERROR",
            "error": "Could not update resource 'decoder/name/ok': Resource 'decoder/name/ok' does not have an associated namespace"
        })"),
        std::make_tuple(3,
                        name.fullName(),
                        "json",
                        successJson.str(),
                        R"({"status":"ERROR","error":"Invalid resource type 'collection' for PUT operation"})"),
        std::make_tuple(4, "", "json", successJson.str(), R"({"status":"ERROR","error":"Missing /name parameter"})"),
        std::make_tuple(5,
                        name.fullName(),
                        "",
                        successJson.str(),
                        R"({"status":"ERROR","error":"Missing or invalid /format parameter"})"),
        std::make_tuple(6, name.fullName(), "json", "", R"({"status":"ERROR","error":"Missing /content parameter"})")));

class CatalogDeleteApiTest : public ::testing::TestWithParam<std::tuple<int, std::string, std::string>>
{
protected:
    void SetUp() override
    {
        logging::testInit();
        m_spCatalog = std::make_shared<api::catalog::Catalog>(getConfig());
    }
    std::shared_ptr<api::catalog::Catalog> m_spCatalog;
};

TEST_P(CatalogDeleteApiTest, ResourseDelete)
{
    auto [execution, name, output] = GetParam();
    api::HandlerSync cmd;
    auto mockRbac = std::make_shared<rbac::mocks::MockRBAC>();
    ASSERT_NO_THROW(cmd = api::catalog::handlers::resourceDelete(m_spCatalog, mockRbac));
    json::Json params;
    params.setObject();

    if (execution != 3)
    {
        params.setString(name, "/name");
    }

    params.setString("ignored", "/namespaceid");

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
    ResourseDelete,
    CatalogDeleteApiTest,
    ::testing::Values(std::make_tuple(1, name.fullName(), R"({"status":"OK"})"),
                      std::make_tuple(2, name.fullName(), R"({"status":"OK"})"),
                      std::make_tuple(3, "", R"({"status":"ERROR","error":"Missing /name parameter"})")));
