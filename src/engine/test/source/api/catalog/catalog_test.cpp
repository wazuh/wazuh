#include "catalogTestShared.hpp"
#include <gtest/gtest.h>

class CatalogTest : public ::testing::Test
{

protected:
    virtual void SetUp()
    {
        // Logging setup
        logging::LoggingConfig logConfig;
        logConfig.logLevel = "off";
        logConfig.filePath = logging::DEFAULT_TESTS_LOG_PATH;
        logging::loggingInit(logConfig);
    }

    virtual void TearDown() {}
};

TEST_F(CatalogTest, Validates)
{
    auto config = getConfig();
    ASSERT_NO_THROW(config.validate());
}

TEST_F(CatalogTest, ValidatesErrorNull)
{
    api::catalog::Config config;
    config.store = std::make_shared<FakeStore>();
    config.validator = nullptr;
    ASSERT_THROW(config.validate(), std::runtime_error);
}

TEST_F(CatalogTest, Builds)
{
    auto config = getConfig();
    ASSERT_NO_THROW(api::catalog::Catalog catalog(config));
}

TEST_F(CatalogTest, BuildsInvalidConfig)
{
    api::catalog::Config config;
    ASSERT_THROW(api::catalog::Catalog catalog(config), std::runtime_error);
}

TEST_F(CatalogTest, GetResourceSpecificJson)
{
    auto config = getConfig();
    api::catalog::Catalog catalog(config);
    std::variant<std::string, base::Error> result;
    ASSERT_NO_THROW(result = catalog.getResource(successResourceAssetJson));
    ASSERT_TRUE(std::holds_alternative<std::string>(result));
    ASSERT_EQ(std::get<std::string>(result), successJson.str());
}

TEST_F(CatalogTest, GetResourceSpecificYml)
{
    auto config = getConfig();
    api::catalog::Catalog catalog(config);
    std::variant<std::string, base::Error> result;
    ASSERT_NO_THROW(result = catalog.getResource(successResourceAssetYml));
    ASSERT_TRUE(std::holds_alternative<std::string>(result));
    ASSERT_EQ(std::get<std::string>(result), successYml);
}

TEST_F(CatalogTest, GetResourceSpecificDriverError)
{
    auto config = getConfig();
    api::catalog::Catalog catalog(config);
    std::variant<std::string, base::Error> result;
    ASSERT_NO_THROW(result = catalog.getResource(failResourceAsset));
    ASSERT_TRUE(std::holds_alternative<base::Error>(result));
}

TEST_F(CatalogTest, GetResourceCollectionJson)
{
    auto config = getConfig();
    api::catalog::Catalog catalog(config);
    std::variant<std::string, base::Error> result;
    ASSERT_NO_THROW(result = catalog.getResource(successCollectionAssetJson));
    ASSERT_TRUE(std::holds_alternative<std::string>(result));
    ASSERT_EQ(std::get<std::string>(result), successCollectionJson.str());
}

TEST_F(CatalogTest, GetResourceCollectionYml)
{
    auto config = getConfig();
    api::catalog::Catalog catalog(config);
    std::variant<std::string, base::Error> result;
    ASSERT_NO_THROW(result = catalog.getResource(successCollectionAssetYml));
    ASSERT_TRUE(std::holds_alternative<std::string>(result));
    ASSERT_EQ(std::get<std::string>(result), successCollectionYml);
}

TEST_F(CatalogTest, PostResourceCollectioJson)
{
    auto config = getConfig();
    api::catalog::Catalog catalog(config);
    std::optional<base::Error> error;
    ASSERT_NO_THROW(error = catalog.postResource(successCollectionAssetJson, successJson.str()));
    ASSERT_FALSE(error);
}

TEST_F(CatalogTest, PostResourceCollectioYml)
{
    auto config = getConfig();
    api::catalog::Catalog catalog(config);
    std::optional<base::Error> error;
    ASSERT_NO_THROW(error = catalog.postResource(successCollectionAssetYml, successYml));
    ASSERT_FALSE(error);
}

TEST_F(CatalogTest, PostResourceCollectioDriverError)
{
    auto config = getConfig();
    api::catalog::Catalog catalog(config);
    std::optional<base::Error> error;
    ASSERT_NO_THROW(error = catalog.postResource(successCollectionAssetJson, successYml));
    ASSERT_TRUE(error);
}

TEST_F(CatalogTest, PostResourceSpecific)
{
    auto config = getConfig();
    api::catalog::Catalog catalog(config);
    std::optional<base::Error> error;
    ASSERT_NO_THROW(error = catalog.postResource(successResourceAssetJson, successJson.str()));
    ASSERT_TRUE(error);
}

TEST_F(CatalogTest, DeleteResourceSpecific)
{
    auto config = getConfig();
    api::catalog::Catalog catalog(config);
    std::optional<base::Error> error;
    ASSERT_NO_THROW(error = catalog.deleteResource(successResourceAssetJson));
    ASSERT_FALSE(error);
}

TEST_F(CatalogTest, DeleteResourceSpecificDriverError)
{
    auto config = getConfig();
    api::catalog::Catalog catalog(config);
    std::optional<base::Error> error;
    ASSERT_NO_THROW(error = catalog.deleteResource(failResourceAsset));
    ASSERT_TRUE(error);
}

TEST_F(CatalogTest, DeleteResourceCollection)
{
    auto config = getConfig();
    api::catalog::Catalog catalog(config);
    std::optional<base::Error> error;
    ASSERT_NO_THROW(error = catalog.deleteResource(successCollectionAssetJson));
    ASSERT_FALSE(error);
}

TEST_F(CatalogTest, PutResourceSpecificJson)
{
    auto config = getConfig();
    api::catalog::Catalog catalog(config);
    std::optional<base::Error> error;
    ASSERT_NO_THROW(error = catalog.putResource(successResourceAssetJson, successJson.str()));
    ASSERT_FALSE(error);
}

TEST_F(CatalogTest, PutResourceSpecificYml)
{
    auto config = getConfig();
    api::catalog::Catalog catalog(config);
    std::optional<base::Error> error;
    ASSERT_NO_THROW(error = catalog.putResource(successResourceAssetYml, successYml));
    ASSERT_FALSE(error);
}

TEST_F(CatalogTest, PutResourceSpecificDriverError)
{
    auto config = getConfig();
    api::catalog::Catalog catalog(config);
    std::optional<base::Error> error;
    ASSERT_NO_THROW(error = catalog.putResource(failResourceAsset, successYml));
    ASSERT_TRUE(error);
}

TEST_F(CatalogTest, PutResourceCollection)
{
    auto config = getConfig();
    api::catalog::Catalog catalog(config);
    std::optional<base::Error> error;
    ASSERT_NO_THROW(error = catalog.putResource(successCollectionAssetJson, successJson.str()));
    ASSERT_TRUE(error);
}

TEST_F(CatalogTest, ValidateResourceSpecificJson)
{
    auto config = getConfig();
    api::catalog::Catalog catalog(config);
    std::optional<base::Error> error;
    ASSERT_NO_THROW(error = catalog.validateResource(successResourceAssetJson, successJson.str()));
    ASSERT_FALSE(error);
}

TEST_F(CatalogTest, ValidateResourceSpecificYml)
{
    auto config = getConfig();
    api::catalog::Catalog catalog(config);
    std::optional<base::Error> error;
    ASSERT_NO_THROW(error = catalog.validateResource(successResourceAssetYml, successYml));
    ASSERT_FALSE(error);
}

TEST_F(CatalogTest, ValidateResourceSpecificDriverError)
{
    auto config = getConfig();
    api::catalog::Catalog catalog(config);
    std::optional<base::Error> error;
    ASSERT_NO_THROW(error = catalog.validateResource(failResourceAsset, successYml));
    ASSERT_TRUE(error);
}

TEST_F(CatalogTest, ValidateResourceCollection)
{
    auto config = getConfig();
    api::catalog::Catalog catalog(config);
    std::optional<base::Error> error;
    ASSERT_NO_THROW(error = catalog.validateResource(successCollectionAssetJson, successJson.str()));
    ASSERT_TRUE(error);
}
