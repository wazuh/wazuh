#include "catalogTestShared.hpp"

#include <api/catalog/commands.hpp>
#include <gtest/gtest.h>

const std::string rCommand {"dummy cmd"};
const std::string rOrigin {"Dummy org module"};


TEST(CatalogCmdsTest, GetResourceCmd)
{
    auto config = getConfig();
    auto catalog = std::make_shared<api::catalog::Catalog>(config);

    base::Name name(
        {api::catalog::Resource::typeToStr(api::catalog::Resource::Type::decoder),
         successName.parts()[1],
         successName.parts()[2]});

    api::Handler cmd;
    ASSERT_NO_THROW(cmd = api::catalog::cmds::resourceGet(catalog));
    json::Json params {
        fmt::format("{{\"name\": \"{}\", \"format\": \"json\"}}", name.fullName())
            .c_str()};


    ASSERT_NO_THROW(cmd(api::wpRequest::create(rCommand, rOrigin, params)));
    auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);
}

TEST(CatalogCmdsTest, GetResourceCmdPersist)
{
    api::Handler cmd;
    base::Name name(
        {api::catalog::Resource::typeToStr(api::catalog::Resource::Type::decoder),
         successName.parts()[1],
         successName.parts()[2]});
    {
        auto config = getConfig();
        auto catalog = std::make_shared<api::catalog::Catalog>(config);

        ASSERT_NO_THROW(cmd = api::catalog::cmds::resourceGet(catalog));
    }
    json::Json params {
        fmt::format("{{\"name\": \"{}\", \"format\": \"json\"}}", name.fullName())
            .c_str()};
    ASSERT_NO_THROW(cmd(api::wpRequest::create(rCommand, rOrigin, params)));
    auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);
}

TEST(CatalogCmdsTest, GetResourceCmdMissingName)
{
    auto config = getConfig();
    auto catalog = std::make_shared<api::catalog::Catalog>(config);

    ASSERT_NO_THROW(api::catalog::cmds::resourceGet(catalog));
    json::Json params {R"({"format": "json"})"};
    auto response = api::catalog::cmds::resourceGet(catalog)(api::wpRequest::create(rCommand, rOrigin, params));
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
}

TEST(CatalogCmdsTest, GetResourceCmdMissingFormat)
{
    auto config = getConfig();
    auto catalog = std::make_shared<api::catalog::Catalog>(config);
    base::Name name(
        {api::catalog::Resource::typeToStr(api::catalog::Resource::Type::decoder),
         successName.parts()[1],
         successName.parts()[2]});

    ASSERT_NO_THROW(api::catalog::cmds::resourceGet(catalog));
    json::Json params {fmt::format(R"({{"name": "{}"}})", name.fullName()).c_str()};
    auto response = api::catalog::cmds::resourceGet(catalog)(api::wpRequest::create(rCommand, rOrigin, params));
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
}

TEST(CatalogCmdsTest, GetResourceCmdCatalogError)
{
    auto config = getConfig();
    auto catalog = std::make_shared<api::catalog::Catalog>(config);
    base::Name name(
        {api::catalog::Resource::typeToStr(api::catalog::Resource::Type::decoder),
         failName.parts()[1],
         failName.parts()[2]});
    ASSERT_NO_THROW(api::catalog::cmds::resourceGet(catalog));
    json::Json params {
        fmt::format("{{\"name\": \"{}\", \"format\": \"json\"}}", name.fullName())
            .c_str()};
    auto response = api::catalog::cmds::resourceGet(catalog)(api::wpRequest::create(rCommand, rOrigin, params));
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
}

TEST(CatalogCmdsTest, GetResourceCmdInvalidFormat)
{
    auto config = getConfig();
    auto catalog = std::make_shared<api::catalog::Catalog>(config);
    base::Name name(
        {api::catalog::Resource::typeToStr(api::catalog::Resource::Type::decoder),
         successName.parts()[1],
         successName.parts()[2]});
    ASSERT_NO_THROW(api::catalog::cmds::resourceGet(catalog));
    json::Json params {
        fmt::format("{{\"name\": \"{}\", \"format\": \"invalid\"}}", name.fullName())
            .c_str()};
    auto response = api::catalog::cmds::resourceGet(catalog)(api::wpRequest::create(rCommand, rOrigin, params));
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
}

TEST(CatalogCmdsTest, GetResourceCmdInvalidName)
{
    auto config = getConfig();
    auto catalog = std::make_shared<api::catalog::Catalog>(config);
    ASSERT_NO_THROW(api::catalog::cmds::resourceGet(catalog));
    json::Json params {"{\"name\": \"invalid\", \"format\": \"json\"}"};
    auto response = api::catalog::cmds::resourceGet(catalog)(api::wpRequest::create(rCommand, rOrigin, params));
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
}

TEST(CatalogCmdsTest, PostResourceCmd)
{
    auto config = getConfig();
    auto catalog = std::make_shared<api::catalog::Catalog>(config);

    base::Name name(
        api::catalog::Resource::typeToStr(api::catalog::Resource::Type::decoder));

    api::Handler cmd;
    ASSERT_NO_THROW(cmd = api::catalog::cmds::resourcePost(catalog));
    json::Json params;
    params.setObject();
    params.setString(name.fullName(), "/name");
    params.setString("json", "/format");
    params.setString(successJson.str(), "/content");
    ASSERT_NO_THROW(cmd(api::wpRequest::create(rCommand, rOrigin, params)));
    auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);
}

TEST(CatalogCmdsTest, PostResourceCmdPersist)
{
    api::Handler cmd;
    base::Name name(
        api::catalog::Resource::typeToStr(api::catalog::Resource::Type::decoder));
    {
        auto config = getConfig();
        auto catalog = std::make_shared<api::catalog::Catalog>(config);

        ASSERT_NO_THROW(cmd = api::catalog::cmds::resourcePost(catalog));
    }
    json::Json params;
    params.setObject();
    params.setString(name.fullName(), "/name");
    params.setString("json", "/format");
    params.setString(successJson.str(), "/content");
    ASSERT_NO_THROW(cmd(api::wpRequest::create(rCommand, rOrigin, params)));
    auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);
}

TEST(CatalogCmdsTest, PostResourceCmdNotCollectionName)
{
    auto config = getConfig();
    auto catalog = std::make_shared<api::catalog::Catalog>(config);

    api::Handler cmd;
    ASSERT_NO_THROW(cmd = api::catalog::cmds::resourcePost(catalog));
    json::Json params;
    params.setObject();
    params.setString(successName.fullName(), "/name");
    params.setString("json", "/format");
    params.setString(successJson.str(), "/content");
    ASSERT_NO_THROW(cmd(api::wpRequest::create(rCommand, rOrigin, params)));
    auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
}

TEST(CatalogCmdsTest, PostResourceCmdMissingName)
{
    auto config = getConfig();
    auto catalog = std::make_shared<api::catalog::Catalog>(config);

    api::Handler cmd;
    ASSERT_NO_THROW(cmd = api::catalog::cmds::resourcePost(catalog));
    json::Json params;
    params.setObject();
    params.setString("json", "/format");
    params.setString(successJson.str(), "/content");
    ASSERT_NO_THROW(cmd(api::wpRequest::create(rCommand, rOrigin, params)));
    auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
}

TEST(CatalogCmdsTest, PostResourceCmdMissingFormat)
{
    auto config = getConfig();
    auto catalog = std::make_shared<api::catalog::Catalog>(config);

    base::Name name(
        api::catalog::Resource::typeToStr(api::catalog::Resource::Type::decoder));

    api::Handler cmd;
    ASSERT_NO_THROW(cmd = api::catalog::cmds::resourcePost(catalog));
    json::Json params;
    params.setObject();
    params.setString(name.fullName(), "/name");
    params.setString(successJson.str(), "/content");
    ASSERT_NO_THROW(cmd(api::wpRequest::create(rCommand, rOrigin, params)));
    auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
}

TEST(CatalogCmdsTest, PostResourceCmdMissingContent)
{
    auto config = getConfig();
    auto catalog = std::make_shared<api::catalog::Catalog>(config);

    base::Name name(
        api::catalog::Resource::typeToStr(api::catalog::Resource::Type::decoder));

    api::Handler cmd;
    ASSERT_NO_THROW(cmd = api::catalog::cmds::resourcePost(catalog));
    json::Json params;
    params.setObject();
    params.setString(name.fullName(), "/name");
    params.setString("json", "/format");
    ASSERT_NO_THROW(cmd(api::wpRequest::create(rCommand, rOrigin, params)));
    auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
}

TEST(CatalogCmdsTest, PutResourceCmd)
{
    auto config = getConfig();
    auto catalog = std::make_shared<api::catalog::Catalog>(config);

    base::Name name(
        {api::catalog::Resource::typeToStr(api::catalog::Resource::Type::decoder),
         successName.parts()[1],
         successName.parts()[2]});

    api::Handler cmd;
    ASSERT_NO_THROW(cmd = api::catalog::cmds::resourcePut(catalog));
    json::Json params;
    params.setObject();
    params.setString(name.fullName(), "/name");
    params.setString("json", "/format");
    params.setString(successJson.str(), "/content");
    ASSERT_NO_THROW(cmd(api::wpRequest::create(rCommand, rOrigin, params)));
    auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);
}

TEST(CatalogCmdsTest, PutResourceCmdPersist)
{
    api::Handler cmd;
    base::Name name(
        {api::catalog::Resource::typeToStr(api::catalog::Resource::Type::decoder),
         successName.parts()[1],
         successName.parts()[2]});
    {
        auto config = getConfig();
        auto catalog = std::make_shared<api::catalog::Catalog>(config);

        ASSERT_NO_THROW(cmd = api::catalog::cmds::resourcePut(catalog));
    }
    json::Json params;
    params.setObject();
    params.setString(name.fullName(), "/name");
    params.setString("json", "/format");
    params.setString(successJson.str(), "/content");
    ASSERT_NO_THROW(cmd(api::wpRequest::create(rCommand, rOrigin, params)));
    auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);
}

TEST(CatalogCmdsTest, PutResourceCmdCollection)
{
    auto config = getConfig();
    auto catalog = std::make_shared<api::catalog::Catalog>(config);

    base::Name name(
        api::catalog::Resource::typeToStr(api::catalog::Resource::Type::decoder));

    api::Handler cmd;
    ASSERT_NO_THROW(cmd = api::catalog::cmds::resourcePut(catalog));
    json::Json params;
    params.setObject();
    params.setString(name.fullName(), "/name");
    params.setString("json", "/format");
    params.setString(successJson.str(), "/content");
    ASSERT_NO_THROW(cmd(api::wpRequest::create(rCommand, rOrigin, params)));
    auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
}

TEST(CatalogCmdsTest, PutResourceCmdMissingName)
{
    auto config = getConfig();
    auto catalog = std::make_shared<api::catalog::Catalog>(config);

    api::Handler cmd;
    ASSERT_NO_THROW(cmd = api::catalog::cmds::resourcePut(catalog));
    json::Json params;
    params.setObject();
    params.setString("json", "/format");
    params.setString(successJson.str(), "/content");
    ASSERT_NO_THROW(cmd(api::wpRequest::create(rCommand, rOrigin, params)));
    auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
}

TEST(CatalogCmdsTest, PutResourceCmdMissingFormat)
{
    auto config = getConfig();
    auto catalog = std::make_shared<api::catalog::Catalog>(config);

    base::Name name(
        api::catalog::Resource::typeToStr(api::catalog::Resource::Type::decoder));

    api::Handler cmd;
    ASSERT_NO_THROW(cmd = api::catalog::cmds::resourcePut(catalog));
    json::Json params;
    params.setObject();
    params.setString(name.fullName(), "/name");
    params.setString(successJson.str(), "/content");
    ASSERT_NO_THROW(cmd(api::wpRequest::create(rCommand, rOrigin, params)));
    auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
}

TEST(CatalogCmdsTest, PutResourceCmdMissingContent)
{
    auto config = getConfig();
    auto catalog = std::make_shared<api::catalog::Catalog>(config);

    base::Name name(
        api::catalog::Resource::typeToStr(api::catalog::Resource::Type::decoder));

    api::Handler cmd;
    ASSERT_NO_THROW(cmd = api::catalog::cmds::resourcePut(catalog));
    json::Json params;
    params.setObject();
    params.setString(name.fullName(), "/name");
    params.setString("json", "/format");
    ASSERT_NO_THROW(cmd(api::wpRequest::create(rCommand, rOrigin, params)));
    auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
}

TEST(CatalogCmdsTest, DeleteResourceCmd)
{
    auto config = getConfig();
    auto catalog = std::make_shared<api::catalog::Catalog>(config);

    base::Name name(
        {api::catalog::Resource::typeToStr(api::catalog::Resource::Type::decoder),
         successName.parts()[1],
         successName.parts()[2]});

    api::Handler cmd;
    ASSERT_NO_THROW(cmd = api::catalog::cmds::resourceDelete(catalog));
    json::Json params;
    params.setObject();
    params.setString(name.fullName(), "/name");
    ASSERT_NO_THROW(cmd(api::wpRequest::create(rCommand, rOrigin, params)));
    auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);
}

TEST(CatalogCmdsTest, DeleteResourceCmdPersist)
{
    api::Handler cmd;
    base::Name name(
        {api::catalog::Resource::typeToStr(api::catalog::Resource::Type::decoder),
         successName.parts()[1],
         successName.parts()[2]});
    {
        auto config = getConfig();
        auto catalog = std::make_shared<api::catalog::Catalog>(config);

        ASSERT_NO_THROW(cmd = api::catalog::cmds::resourceDelete(catalog));
    }
    json::Json params;
    params.setObject();
    params.setString(name.fullName(), "/name");
    ASSERT_NO_THROW(cmd(api::wpRequest::create(rCommand, rOrigin, params)));
    auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);
}

TEST(CatalogCmdsTest, DeleteResourceCmdCollection)
{
    auto config = getConfig();
    auto catalog = std::make_shared<api::catalog::Catalog>(config);

    base::Name name(
        api::catalog::Resource::typeToStr(api::catalog::Resource::Type::decoder));

    api::Handler cmd;
    ASSERT_NO_THROW(cmd = api::catalog::cmds::resourceDelete(catalog));
    json::Json params;
    params.setObject();
    params.setString(name.fullName(), "/name");
    ASSERT_NO_THROW(cmd(api::wpRequest::create(rCommand, rOrigin, params)));
    auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);
}

TEST(CatalogCmdsTest, DeleteResourceCmdMissingName)
{
    auto config = getConfig();
    auto catalog = std::make_shared<api::catalog::Catalog>(config);

    api::Handler cmd;
    ASSERT_NO_THROW(cmd = api::catalog::cmds::resourceDelete(catalog));
    json::Json params;
    params.setObject();
    ASSERT_NO_THROW(cmd(api::wpRequest::create(rCommand, rOrigin, params)));
    auto response = cmd(api::wpRequest::create(rCommand, rOrigin, params));
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
}

TEST(CatalogCmdsTest, registerHandlers)
{
    auto config = getConfig();
    auto catalog = std::make_shared<api::catalog::Catalog>(config);
    auto apiReg = std::make_shared<api::Registry>();

    ASSERT_NO_THROW(api::catalog::cmds::registerHandlers(catalog, apiReg));
    api::Handler cmd;
    ASSERT_NO_THROW(cmd = apiReg->getHandler("get_catalog"));
    ASSERT_NO_THROW(cmd = apiReg->getHandler("put_catalog"));
    ASSERT_NO_THROW(cmd = apiReg->getHandler("delete_catalog"));
    ASSERT_NO_THROW(cmd = apiReg->getHandler("post_catalog"));
}
