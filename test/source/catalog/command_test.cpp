#include "catalogTestShared.hpp"
#include <catalog/commands.hpp>
#include <gtest/gtest.h>

TEST(CatalogCmdsTest, GetAssetCmd)
{
    auto config = getConfig();
    auto catalog = std::make_shared<catalog::Catalog>(config);

    auto name = successName;
    name.m_type = catalog::typeToString(catalog::Type::DECODER);

    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = catalog::cmds::getAssetCmd(catalog));
    json::Json params {
        fmt::format("{{\"name\": \"{}\", \"format\": \"json\"}}", name.fullName())
            .c_str()};
    ASSERT_NO_THROW(cmd(params));
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);
}

TEST(CatalogCmdsTest, GetAssetCmdPersists)
{
    api::CommandFn cmd;
    auto name = successName;
    name.m_type = catalog::typeToString(catalog::Type::DECODER);
    {
        auto config = getConfig();
        auto catalog = std::make_shared<catalog::Catalog>(config);

        ASSERT_NO_THROW(cmd = catalog::cmds::getAssetCmd(catalog));
    }
    json::Json params {
        fmt::format("{{\"name\": \"{}\", \"format\": \"json\"}}", name.fullName())
            .c_str()};
    ASSERT_NO_THROW(cmd(params));
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);
}

TEST(CatalogCmdsTest, GetAssetCmdMissingName)
{
    auto config = getConfig();
    auto catalog = std::make_shared<catalog::Catalog>(config);

    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = catalog::cmds::getAssetCmd(catalog));
    json::Json params {R"({"format": "json"})"};
    ASSERT_NO_THROW(cmd(params));
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
}

TEST(CatalogCmdsTest, GetAssetCmdMissingFormat)
{
    auto config = getConfig();
    auto catalog = std::make_shared<catalog::Catalog>(config);

    auto name = successName;
    name.m_type = catalog::typeToString(catalog::Type::DECODER);

    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = catalog::cmds::getAssetCmd(catalog));
    json::Json params {fmt::format("{{\"name\": \"{}\"}}", name.fullName()).c_str()};
    ASSERT_NO_THROW(cmd(params));
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
}

TEST(CatalogCmdsTest, GetAssetCmdCatalogError)
{
    auto config = getConfig();
    auto catalog = std::make_shared<catalog::Catalog>(config);

    auto name = failName;
    name.m_type = catalog::typeToString(catalog::Type::DECODER);

    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = catalog::cmds::getAssetCmd(catalog));
    json::Json params {
        fmt::format("{{\"name\": \"{}\", \"format\": \"json\"}}", name.fullName())
            .c_str()};
    ASSERT_NO_THROW(cmd(params));
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
}

TEST(CatalogCmdsTest, PostAssetCmd)
{
    auto config = getConfig();
    auto catalog = std::make_shared<catalog::Catalog>(config);

    auto name = successName;
    name.m_type = catalog::typeToString(catalog::Type::DECODER);

    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = catalog::cmds::postAssetCmd(catalog));
    json::Json params {
        fmt::format("{{\"name\": \"{}\", \"format\": \"json\", \"content\": \"{}\"}}",
                    name.fullName(),
                    validJson.str())
            .c_str()};
    ASSERT_NO_THROW(cmd(params));
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);
}

TEST(CatalogCmdsTest, PostAssetCmdPersists)
{
    api::CommandFn cmd;
    auto name = successName;
    name.m_type = catalog::typeToString(catalog::Type::DECODER);
    {
        auto config = getConfig();
        auto catalog = std::make_shared<catalog::Catalog>(config);

        ASSERT_NO_THROW(cmd = catalog::cmds::postAssetCmd(catalog));
    }
    json::Json params {
        fmt::format("{{\"name\": \"{}\", \"format\": \"json\", \"content\": \"{}\"}}",
                    name.fullName(),
                    validJson.str())
            .c_str()};
    ASSERT_NO_THROW(cmd(params));
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);
}

TEST(CatalogCmdsTest, PostAssetCmdMissingName)
{
    auto config = getConfig();
    auto catalog = std::make_shared<catalog::Catalog>(config);

    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = catalog::cmds::postAssetCmd(catalog));
    json::Json params {
        fmt::format("{{\"format\": \"json\", \"content\": \"{}\"}}", validJson.str())
            .c_str()};
    ASSERT_NO_THROW(cmd(params));
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
}

TEST(CatalogCmdsTest, PostAssetCmdMissingFormat)
{
    auto config = getConfig();
    auto catalog = std::make_shared<catalog::Catalog>(config);

    auto name = successName;
    name.m_type = catalog::typeToString(catalog::Type::DECODER);

    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = catalog::cmds::postAssetCmd(catalog));
    json::Json params {fmt::format("{{\"name\": \"{}\", \"content\": \"{}\"}}",
                                   name.fullName(),
                                   validJson.str())
                           .c_str()};
    ASSERT_NO_THROW(cmd(params));
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
}

TEST(CatalogCmdsTest, PostAssetCmdMissingContent)
{
    auto config = getConfig();
    auto catalog = std::make_shared<catalog::Catalog>(config);

    auto name = successName;
    name.m_type = catalog::typeToString(catalog::Type::DECODER);

    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = catalog::cmds::postAssetCmd(catalog));
    json::Json params {
        fmt::format("{{\"name\": \"{}\", \"format\": \"json\"}}", name.fullName())
            .c_str()};
    ASSERT_NO_THROW(cmd(params));
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
}

TEST(CatalogCmdsTest, PostAssetCmdCatalogError)
{
    auto config = getConfig();
    auto catalog = std::make_shared<catalog::Catalog>(config);

    auto name = failName;
    name.m_type = catalog::typeToString(catalog::Type::DECODER);

    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = catalog::cmds::postAssetCmd(catalog));
    json::Json params {
        fmt::format("{{\"name\": \"{}\", \"format\": \"json\", \"content\": \"{}\"}}",
                    name.fullName(),
                    validJson.str())
            .c_str()};
    ASSERT_NO_THROW(cmd(params));
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
}

TEST(CatalogCmdsTest, DeleteAssetCmd)
{
    auto config = getConfig();
    auto catalog = std::make_shared<catalog::Catalog>(config);

    auto name = successName;
    name.m_type = catalog::typeToString(catalog::Type::DECODER);

    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = catalog::cmds::deleteAssetCmd(catalog));
    json::Json params {
        fmt::format("{{\"name\": \"{}\"}}", name.fullName())
            .c_str()};
    ASSERT_NO_THROW(cmd(params));
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);
}

TEST(CatalogCmdsTest, DeleteAssetCmdPersists)
{
    api::CommandFn cmd;
    auto name = successName;
    name.m_type = catalog::typeToString(catalog::Type::DECODER);
    {
        auto config = getConfig();
        auto catalog = std::make_shared<catalog::Catalog>(config);

        ASSERT_NO_THROW(cmd = catalog::cmds::deleteAssetCmd(catalog));
    }
    json::Json params {
        fmt::format("{{\"name\": \"{}\"}}", name.fullName())
            .c_str()};
    ASSERT_NO_THROW(cmd(params));
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 200);
}

TEST(CatalogCmdsTest, DeleteAssetCmdMissingName)
{
    auto config = getConfig();
    auto catalog = std::make_shared<catalog::Catalog>(config);

    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = catalog::cmds::deleteAssetCmd(catalog));
    json::Json params {"{}"};
    ASSERT_NO_THROW(cmd(params));
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
}

TEST(CatalogCmdsTest, DeleteAssetCmdCatalogError)
{
    auto config = getConfig();
    auto catalog = std::make_shared<catalog::Catalog>(config);

    auto name = failName;
    name.m_type = catalog::typeToString(catalog::Type::DECODER);

    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = catalog::cmds::deleteAssetCmd(catalog));
    json::Json params {
        fmt::format("{{\"name\": \"{}\"}}", name.fullName())
            .c_str()};
    ASSERT_NO_THROW(cmd(params));
    auto response = cmd(params);
    ASSERT_TRUE(response.isValid());
    ASSERT_EQ(response.error(), 400);
}

TEST(CatalogCmdsTest, RegisterAllCmds)
{
    auto config = getConfig();
    auto catalog = std::make_shared<catalog::Catalog>(config);
    auto apiReg = std::make_shared<api::Registry>();

    ASSERT_NO_THROW(catalog::cmds::registerAllCmds(catalog, apiReg));
    api::CommandFn cmd;
    ASSERT_NO_THROW(cmd = apiReg->getCallback("get_asset"));
    ASSERT_NO_THROW(cmd = apiReg->getCallback("post_asset"));
    ASSERT_NO_THROW(cmd = apiReg->getCallback("delete_asset"));
}
