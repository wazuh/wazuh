#include "catalogTestShared.hpp"
#include <gtest/gtest.h>

TEST(CatalogConfigurationTest, Validates)
{
    auto config = getConfig();
    ASSERT_NO_THROW(config.validate());
}

TEST(CatalogConfigurationTest, ValidatesErrorNull)
{
    catalog::Config config;
    config.store = std::make_shared<FakeStore>();
    config.validator = nullptr;
    ASSERT_THROW(config.validate(), std::runtime_error);
}

TEST(CatalogTest, Builds)
{
    auto config = getConfig();
    ASSERT_NO_THROW(catalog::Catalog catalog(config));
}

TEST(CatalogTest, BuildsInvalidConfig)
{
    catalog::Config config;
    ASSERT_THROW(catalog::Catalog catalog(config), std::runtime_error);
}

TEST(CatalogTest, JsonGetAsset)
{
    auto config = getConfig();
    catalog::Catalog catalog(config);
    std::variant<std::string, base::Error> result;
    auto name = successName;
    name.m_type = catalog::typeToString(catalog::Type::DECODER);
    ASSERT_NO_THROW(result = catalog.getAsset(name, catalog::Format::JSON));
    ASSERT_TRUE(std::holds_alternative<std::string>(result));
    ASSERT_EQ(std::get<std::string>(result), successJson.str());
}

TEST(CatalogTest, YmlGetAsset)
{
    auto config = getConfig();
    catalog::Catalog catalog(config);
    std::variant<std::string, base::Error> result;
    auto name = successName;
    name.m_type = catalog::typeToString(catalog::Type::DECODER);
    ASSERT_NO_THROW(result = catalog.getAsset(name, catalog::Format::YAML));
    ASSERT_TRUE(std::holds_alternative<std::string>(result));
    ASSERT_EQ(std::get<std::string>(result), successYml);
}

TEST(CatalogTest, GetAssetNotSupportedType)
{
    auto config = getConfig();
    catalog::Catalog catalog(config);
    std::variant<std::string, base::Error> result;
    auto name = successName;
    name.m_type = "not_supported";
    ASSERT_NO_THROW(result = catalog.getAsset(name, catalog::Format::JSON));
    ASSERT_TRUE(std::holds_alternative<base::Error>(result));
}

TEST(CatalogTest, GetAssetDriverError)
{
    auto config = getConfig();
    catalog::Catalog catalog(config);
    std::variant<std::string, base::Error> result;
    auto name = failName;
    name.m_type = catalog::typeToString(catalog::Type::DECODER);
    ASSERT_NO_THROW(result = catalog.getAsset(name, catalog::Format::JSON));
    ASSERT_TRUE(std::holds_alternative<base::Error>(result));
}

TEST(CatalogTest, JsonAddAsset)
{
    auto config = getConfig();
    catalog::Catalog catalog(config);
    std::optional<base::Error> error;
    auto name = successName;
    name.m_type = catalog::typeToString(catalog::Type::DECODER);
    ASSERT_NO_THROW(error = catalog.addAsset(name, successJson.str(), catalog::Format::JSON));
    ASSERT_FALSE(error);
    ASSERT_TRUE(std::reinterpret_pointer_cast<FakeStore>(config.store)->lastAdded.get());
    ASSERT_EQ(*std::static_pointer_cast<FakeStore>(config.store)->lastAdded, successJson);
}

TEST(CatalogTest, YmlAddAsset)
{
    auto config = getConfig();
    catalog::Catalog catalog(config);
    std::optional<base::Error> error;
    auto name = successName;
    name.m_type = catalog::typeToString(catalog::Type::DECODER);
    ASSERT_NO_THROW(error = catalog.addAsset(name, successYml, catalog::Format::YAML));
    ASSERT_FALSE(error);
    ASSERT_TRUE(std::reinterpret_pointer_cast<FakeStore>(config.store)->lastAdded);
    ASSERT_EQ(*std::static_pointer_cast<FakeStore>(config.store)->lastAdded, successJson);
}

TEST(CatalogTest, AddAssetNotSupportedType)
{
    auto config = getConfig();
    catalog::Catalog catalog(config);
    std::optional<base::Error> error;
    auto name = successName;
    name.m_type = "not_supported";
    ASSERT_NO_THROW(error = catalog.addAsset(name, successJson.str(), catalog::Format::JSON));
    ASSERT_TRUE(error);
}

TEST(CatalogTest, AddAssetDriverError)
{
    auto config = getConfig();
    catalog::Catalog catalog(config);
    std::optional<base::Error> error;
    auto name = failName;
    name.m_type = catalog::typeToString(catalog::Type::DECODER);
    ASSERT_NO_THROW(error = catalog.addAsset(name, successJson.str(), catalog::Format::JSON));
    ASSERT_TRUE(error);
}

TEST(CatalogTest, DelAsset)
{
    auto config = getConfig();
    catalog::Catalog catalog(config);
    std::optional<base::Error> error;
    auto name = successName;
    name.m_type = catalog::typeToString(catalog::Type::DECODER);
    ASSERT_NO_THROW(error = catalog.delAsset(name));
    ASSERT_FALSE(error);
}

TEST(CatalogTest, DelAssetNotSupportedType)
{
    auto config = getConfig();
    catalog::Catalog catalog(config);
    std::optional<base::Error> error;
    auto name = successName;
    name.m_type = "not_supported";
    ASSERT_NO_THROW(error = catalog.delAsset(name));
    ASSERT_TRUE(error);
}

TEST(CatalogTest, DelAssetDriverError)
{
    auto config = getConfig();
    catalog::Catalog catalog(config);
    std::optional<base::Error> error;
    auto name = failName;
    name.m_type = catalog::typeToString(catalog::Type::DECODER);
    ASSERT_NO_THROW(error = catalog.delAsset(name));
    ASSERT_TRUE(error);
}

TEST(CatalogTest, ValidateEnvironment)
{
    auto config = getConfig();
    catalog::Catalog catalog(config);
    std::optional<base::Error> error;
    ASSERT_NO_THROW(error = catalog.validateEnvironment(validJson));
    ASSERT_FALSE(error);
}

TEST(CatalogTest, ValidateEnvironmentDriverError)
{
    auto config = getConfig();
    catalog::Catalog catalog(config);
    std::optional<base::Error> error;
    ASSERT_NO_THROW(error = catalog.validateEnvironment(invalidJson));
    ASSERT_TRUE(error);
}

TEST(CatalogTest, ValidateAsset)
{
    auto config = getConfig();
    catalog::Catalog catalog(config);
    std::optional<base::Error> error;
    ASSERT_NO_THROW(error = catalog.validateAsset(validJson));
    ASSERT_FALSE(error);
}

TEST(CatalogTest, ValidateAssetDriverError)
{
    auto config = getConfig();
    catalog::Catalog catalog(config);
    std::optional<base::Error> error;
    ASSERT_NO_THROW(error = catalog.validateAsset(invalidJson));
    ASSERT_TRUE(error);
}
