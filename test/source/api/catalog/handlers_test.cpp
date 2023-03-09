#include "catalogTestShared.hpp"

#include <api/catalog/handlers.hpp>
#include <gtest/gtest.h>

const std::string rCommand {"dummy cmd"};
const std::string rOrigin {"Dummy org module"};

TEST(Handlers, resourseGet)
{
    auto config = getConfig();
    auto catalog = std::make_shared<api::catalog::Catalog>(config);

    base::Name name({api::catalog::Resource::typeToStr(api::catalog::Resource::Type::decoder),
                     successName.parts()[1],
                     successName.parts()[2]});

    api::Handler cmd;
    ASSERT_NO_THROW(cmd = api::catalog::handlers::resourceGet(catalog));
    json::Json params {fmt::format("{{\"name\": \"{}\", \"format\": \"json\"}}", name.fullName()).c_str()};

    ASSERT_NO_THROW(cmd(api::wpRequest::create(rCommand, rOrigin, params)));
    auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));
    const auto expectedData = json::Json(R"({"status":"OK","content":"{\"name\":\"decoder/name/ok\"}"})");

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Expected: " << expectedData.prettyStr() << std::endl
                                             << "Actual: " << response.data().prettyStr() << std::endl;
}

TEST(Handlers, resourseGet_Persist)
{
    api::Handler cmd;
    base::Name name({api::catalog::Resource::typeToStr(api::catalog::Resource::Type::decoder),
                     successName.parts()[1],
                     successName.parts()[2]});
    {
        auto config = getConfig();
        auto catalog = std::make_shared<api::catalog::Catalog>(config);

        ASSERT_NO_THROW(cmd = api::catalog::handlers::resourceGet(catalog));
    }
    json::Json params {fmt::format("{{\"name\": \"{}\", \"format\": \"json\"}}", name.fullName()).c_str()};
    ASSERT_NO_THROW(cmd(api::wpRequest::create(rCommand, rOrigin, params)));
    auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));
    const auto expectedData = json::Json(R"({"status":"OK","content":"{\"name\":\"decoder/name/ok\"}"})");

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Expected: " << expectedData.prettyStr() << std::endl
                                             << "Actual: " << response.data().prettyStr() << std::endl;
}

TEST(Handlers, resourseGet_MissingName)
{
    auto config = getConfig();
    auto catalog = std::make_shared<api::catalog::Catalog>(config);

    ASSERT_NO_THROW(api::catalog::handlers::resourceGet(catalog));
    json::Json params {R"({"format": "json"})"};
    auto response = api::catalog::handlers::resourceGet(catalog)(api::wpRequest::create(rCommand, rOrigin, params));
    const auto expectedData = json::Json(R"({"status":"ERROR","error":"Missing /name parameter"})");

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Expected: " << expectedData.prettyStr() << std::endl
                                             << "Actual: " << response.data().prettyStr() << std::endl;
}

TEST(Handlers, resourseGet_MissingFormat)
{
    auto config = getConfig();
    auto catalog = std::make_shared<api::catalog::Catalog>(config);
    base::Name name({api::catalog::Resource::typeToStr(api::catalog::Resource::Type::decoder),
                     successName.parts()[1],
                     successName.parts()[2]});

    ASSERT_NO_THROW(api::catalog::handlers::resourceGet(catalog));
    json::Json params {fmt::format(R"({{"name": "{}"}})", name.fullName()).c_str()};
    auto response = api::catalog::handlers::resourceGet(catalog)(api::wpRequest::create(rCommand, rOrigin, params));
    const auto expectedData = json::Json(R"({"status":"ERROR","error":"Missing or invalid /format parameter"})");

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Expected: " << expectedData.prettyStr() << std::endl
                                             << "Actual: " << response.data().prettyStr() << std::endl;
}

TEST(Handlers, resourseGet_CatalogError)
{
    auto config = getConfig();
    auto catalog = std::make_shared<api::catalog::Catalog>(config);
    base::Name name({api::catalog::Resource::typeToStr(api::catalog::Resource::Type::decoder),
                     failName.parts()[1],
                     failName.parts()[2]});
    ASSERT_NO_THROW(api::catalog::handlers::resourceGet(catalog));
    json::Json params {fmt::format("{{\"name\": \"{}\", \"format\": \"json\"}}", name.fullName()).c_str()};
    auto response = api::catalog::handlers::resourceGet(catalog)(api::wpRequest::create(rCommand, rOrigin, params));
    const auto expectedData = json::Json(
        R"({"status":"ERROR","error":"Content \"decoder/name/fail\" could not be obtained from store: error"})");

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Expected: " << expectedData.prettyStr() << std::endl
                                             << "Actual: " << response.data().prettyStr() << std::endl;
}

TEST(Handlers, resourseGet_InvalidFormat)
{
    auto config = getConfig();
    auto catalog = std::make_shared<api::catalog::Catalog>(config);
    base::Name name({api::catalog::Resource::typeToStr(api::catalog::Resource::Type::decoder),
                     successName.parts()[1],
                     successName.parts()[2]});
    ASSERT_NO_THROW(api::catalog::handlers::resourceGet(catalog));
    json::Json params {fmt::format("{{\"name\": \"{}\", \"format\": \"invalid\"}}", name.fullName()).c_str()};
    auto response = api::catalog::handlers::resourceGet(catalog)(api::wpRequest::create(rCommand, rOrigin, params));
    const auto expectedData = json::Json(R"({"status":"ERROR","error":"Missing or invalid /format parameter"})");

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Expected: " << expectedData.prettyStr() << std::endl
                                             << "Actual: " << response.data().prettyStr() << std::endl;
}

TEST(Handlers, resourseGet_InvalidName)
{
    auto config = getConfig();
    auto catalog = std::make_shared<api::catalog::Catalog>(config);
    ASSERT_NO_THROW(api::catalog::handlers::resourceGet(catalog));
    json::Json params {"{\"name\": \"invalid\", \"format\": \"json\"}"};
    auto response = api::catalog::handlers::resourceGet(catalog)(api::wpRequest::create(rCommand, rOrigin, params));
    const auto expectedData = json::Json(R"({"status":"ERROR","error":"Invalid collection type \"invalid\""})");

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Expected: " << expectedData.prettyStr() << std::endl
                                             << "Actual: " << response.data().prettyStr() << std::endl;
}

TEST(Handlers, resourcePost)
{
    auto config = getConfig();
    auto catalog = std::make_shared<api::catalog::Catalog>(config);

    base::Name name(api::catalog::Resource::typeToStr(api::catalog::Resource::Type::decoder));

    api::Handler cmd;
    ASSERT_NO_THROW(cmd = api::catalog::handlers::resourcePost(catalog));
    json::Json params;
    params.setObject();
    params.setString(name.fullName(), "/type");
    params.setString("json", "/format");
    params.setString(successJson.str(), "/content");
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

TEST(Handlers, resourcePost_Persist)
{
    api::Handler cmd;
    base::Name name(api::catalog::Resource::typeToStr(api::catalog::Resource::Type::decoder));
    {
        auto config = getConfig();
        auto catalog = std::make_shared<api::catalog::Catalog>(config);

        ASSERT_NO_THROW(cmd = api::catalog::handlers::resourcePost(catalog));
    }
    json::Json params;
    params.setObject();
    params.setString(name.fullName(), "/type");
    params.setString("json", "/format");
    params.setString(successJson.str(), "/content");
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

TEST(Handlers, resourcePost_NotCollectionType)
{
    auto config = getConfig();
    auto catalog = std::make_shared<api::catalog::Catalog>(config);

    api::Handler cmd;
    ASSERT_NO_THROW(cmd = api::catalog::handlers::resourcePost(catalog));
    json::Json params;
    params.setObject();
    params.setString(successName.fullName(), "/type");
    params.setString("json", "/format");
    params.setString(successJson.str(), "/content");
    ASSERT_NO_THROW(cmd(api::wpRequest::create(rCommand, rOrigin, params)));
    auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));
    const auto expectedData = json::Json(R"({"status":"ERROR","error":"Missing /type parameter or is invalid"})");

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Expected: " << expectedData.prettyStr() << std::endl
                                             << "Actual: " << response.data().prettyStr() << std::endl;
}

TEST(Handlers, resourcePost_MissingType)
{
    auto config = getConfig();
    auto catalog = std::make_shared<api::catalog::Catalog>(config);

    api::Handler cmd;
    ASSERT_NO_THROW(cmd = api::catalog::handlers::resourcePost(catalog));
    json::Json params;
    params.setObject();
    params.setString("json", "/format");
    params.setString(successJson.str(), "/content");
    ASSERT_NO_THROW(cmd(api::wpRequest::create(rCommand, rOrigin, params)));
    auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));
    const auto expectedData = json::Json(R"({"status":"ERROR","error":"Missing /type parameter or is invalid"})");

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Expected: " << expectedData.prettyStr() << std::endl
                                             << "Actual: " << response.data().prettyStr() << std::endl;
}

TEST(Handlers, resourcePost_MissingFormat)
{
    auto config = getConfig();
    auto catalog = std::make_shared<api::catalog::Catalog>(config);

    base::Name name(api::catalog::Resource::typeToStr(api::catalog::Resource::Type::decoder));

    api::Handler cmd;
    ASSERT_NO_THROW(cmd = api::catalog::handlers::resourcePost(catalog));
    json::Json params;
    params.setObject();
    params.setString(name.fullName(), "/type");
    params.setString(successJson.str(), "/content");
    ASSERT_NO_THROW(cmd(api::wpRequest::create(rCommand, rOrigin, params)));
    auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));
    const auto expectedData = json::Json(R"({"status":"ERROR","error":"Missing /format parameter or is invalid"})");

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Expected: " << expectedData.prettyStr() << std::endl
                                             << "Actual: " << response.data().prettyStr() << std::endl;
}

TEST(Handlers, resourcePost_MissingContent)
{
    auto config = getConfig();
    auto catalog = std::make_shared<api::catalog::Catalog>(config);

    base::Name name(api::catalog::Resource::typeToStr(api::catalog::Resource::Type::decoder));

    api::Handler cmd;
    ASSERT_NO_THROW(cmd = api::catalog::handlers::resourcePost(catalog));
    json::Json params;
    params.setObject();
    params.setString(name.fullName(), "/type");
    params.setString("json", "/format");
    ASSERT_NO_THROW(cmd(api::wpRequest::create(rCommand, rOrigin, params)));
    auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));
    const auto expectedData = json::Json(R"({"status":"ERROR","error":"Missing /content parameter"})");

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Expected: " << expectedData.prettyStr() << std::endl
                                             << "Actual: " << response.data().prettyStr() << std::endl;
}

TEST(Handlers, resourcePut)
{
    auto config = getConfig();
    auto catalog = std::make_shared<api::catalog::Catalog>(config);

    base::Name name({api::catalog::Resource::typeToStr(api::catalog::Resource::Type::decoder),
                     successName.parts()[1],
                     successName.parts()[2]});

    api::Handler cmd;
    ASSERT_NO_THROW(cmd = api::catalog::handlers::resourcePut(catalog));
    json::Json params;
    params.setObject();
    params.setString(name.fullName(), "/name");
    params.setString("json", "/format");
    params.setString(successJson.str(), "/content");
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

TEST(Handlers, resourcePut_Persist)
{
    api::Handler cmd;
    base::Name name({api::catalog::Resource::typeToStr(api::catalog::Resource::Type::decoder),
                     successName.parts()[1],
                     successName.parts()[2]});
    {
        auto config = getConfig();
        auto catalog = std::make_shared<api::catalog::Catalog>(config);

        ASSERT_NO_THROW(cmd = api::catalog::handlers::resourcePut(catalog));
    }
    json::Json params;
    params.setObject();
    params.setString(name.fullName(), "/name");
    params.setString("json", "/format");
    params.setString(successJson.str(), "/content");
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

TEST(Handlers, resourcePut_Collection)
{
    auto config = getConfig();
    auto catalog = std::make_shared<api::catalog::Catalog>(config);

    base::Name name(api::catalog::Resource::typeToStr(api::catalog::Resource::Type::decoder));

    api::Handler cmd;
    ASSERT_NO_THROW(cmd = api::catalog::handlers::resourcePut(catalog));
    json::Json params;
    params.setObject();
    params.setString(name.fullName(), "/name");
    params.setString("json", "/format");
    params.setString(successJson.str(), "/content");
    ASSERT_NO_THROW(cmd(api::wpRequest::create(rCommand, rOrigin, params)));
    auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));
    const auto expectedData =
        json::Json(R"({"status":"ERROR","error":"Invalid resource type \"collection\" for PUT operation"})");

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Expected: " << expectedData.prettyStr() << std::endl
                                             << "Actual: " << response.data().prettyStr() << std::endl;
}

TEST(Handlers, resourcePut_MissingName)
{
    auto config = getConfig();
    auto catalog = std::make_shared<api::catalog::Catalog>(config);

    api::Handler cmd;
    ASSERT_NO_THROW(cmd = api::catalog::handlers::resourcePut(catalog));
    json::Json params;
    params.setObject();
    params.setString("json", "/format");
    params.setString(successJson.str(), "/content");
    ASSERT_NO_THROW(cmd(api::wpRequest::create(rCommand, rOrigin, params)));
    auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));
    const auto expectedData = json::Json(R"({"status":"ERROR","error":"Missing /name parameter"})");

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Expected: " << expectedData.prettyStr() << std::endl
                                             << "Actual: " << response.data().prettyStr() << std::endl;
}

TEST(Handlers, resourcePut_MissingFormat)
{
    auto config = getConfig();
    auto catalog = std::make_shared<api::catalog::Catalog>(config);

    base::Name name(api::catalog::Resource::typeToStr(api::catalog::Resource::Type::decoder));

    api::Handler cmd;
    ASSERT_NO_THROW(cmd = api::catalog::handlers::resourcePut(catalog));
    json::Json params;
    params.setObject();
    params.setString(name.fullName(), "/name");
    params.setString(successJson.str(), "/content");
    ASSERT_NO_THROW(cmd(api::wpRequest::create(rCommand, rOrigin, params)));
    auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));
    const auto expectedData = json::Json(R"({"status":"ERROR","error":"Missing or invalid /format parameter"})");

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Expected: " << expectedData.prettyStr() << std::endl
                                             << "Actual: " << response.data().prettyStr() << std::endl;
}

TEST(Handlers, resourcePut_MissingContent)
{
    auto config = getConfig();
    auto catalog = std::make_shared<api::catalog::Catalog>(config);

    base::Name name(api::catalog::Resource::typeToStr(api::catalog::Resource::Type::decoder));

    api::Handler cmd;
    ASSERT_NO_THROW(cmd = api::catalog::handlers::resourcePut(catalog));
    json::Json params;
    params.setObject();
    params.setString(name.fullName(), "/name");
    params.setString("json", "/format");
    ASSERT_NO_THROW(cmd(api::wpRequest::create(rCommand, rOrigin, params)));
    auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));
    const auto expectedData = json::Json(R"({"status":"ERROR","error":"Missing /content parameter"})");

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Expected: " << expectedData.prettyStr() << std::endl
                                             << "Actual: " << response.data().prettyStr() << std::endl;
}

TEST(Handlers, resourceDelete)
{
    auto config = getConfig();
    auto catalog = std::make_shared<api::catalog::Catalog>(config);

    base::Name name({api::catalog::Resource::typeToStr(api::catalog::Resource::Type::decoder),
                     successName.parts()[1],
                     successName.parts()[2]});

    api::Handler cmd;
    ASSERT_NO_THROW(cmd = api::catalog::handlers::resourceDelete(catalog));
    json::Json params;
    params.setObject();
    params.setString(name.fullName(), "/name");
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

TEST(Handlers, resourceDelete_Persist)
{
    api::Handler cmd;
    base::Name name({api::catalog::Resource::typeToStr(api::catalog::Resource::Type::decoder),
                     successName.parts()[1],
                     successName.parts()[2]});
    {
        auto config = getConfig();
        auto catalog = std::make_shared<api::catalog::Catalog>(config);

        ASSERT_NO_THROW(cmd = api::catalog::handlers::resourceDelete(catalog));
    }
    json::Json params;
    params.setObject();
    params.setString(name.fullName(), "/name");
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

TEST(Handlers, resourceDelete_Collection)
{
    auto config = getConfig();
    auto catalog = std::make_shared<api::catalog::Catalog>(config);

    base::Name name(api::catalog::Resource::typeToStr(api::catalog::Resource::Type::decoder));

    api::Handler cmd;
    ASSERT_NO_THROW(cmd = api::catalog::handlers::resourceDelete(catalog));
    json::Json params;
    params.setObject();
    params.setString(name.fullName(), "/name");
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

TEST(Handlers, resourceDelete_MissingName)
{
    auto config = getConfig();
    auto catalog = std::make_shared<api::catalog::Catalog>(config);

    api::Handler cmd;
    ASSERT_NO_THROW(cmd = api::catalog::handlers::resourceDelete(catalog));
    json::Json params;
    params.setObject();
    ASSERT_NO_THROW(cmd(api::wpRequest::create(rCommand, rOrigin, params)));
    auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));
    const auto expectedData = json::Json(R"({"status":"ERROR","error":"Missing /name parameter"})");

    // check response
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 0);
    ASSERT_FALSE(response.message().has_value());
    ASSERT_EQ(response.data(), expectedData) << "Expected: " << expectedData.prettyStr() << std::endl
                                             << "Actual: " << response.data().prettyStr() << std::endl;
}

TEST(Handlers, registerHandlers)
{
    auto config = getConfig();
    auto catalog = std::make_shared<api::catalog::Catalog>(config);
    auto apiReg = std::make_shared<api::Registry>();

    ASSERT_NO_THROW(api::catalog::handlers::registerHandlers(catalog, apiReg));
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = apiReg->getHandler("catalog.resource/post"));
    ASSERT_NO_THROW(cmd = apiReg->getHandler("catalog.resource/get"));
    ASSERT_NO_THROW(cmd = apiReg->getHandler("catalog.resource/put"));
    ASSERT_NO_THROW(cmd = apiReg->getHandler("catalog.resource/delete"));
    ASSERT_NO_THROW(cmd = apiReg->getHandler("catalog.resource/validate"));
}
