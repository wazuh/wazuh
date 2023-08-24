#include <gtest/gtest.h>

#include "../../apiAuxiliarFunctions.hpp"
#include "catalogTestShared.hpp"

constexpr auto COMMAND_FAILED_CASE {3};

class CatalogGetTest : public ::testing::TestWithParam<std::tuple<int, api::catalog::Resource, std::string>>
{
protected:
    void SetUp() override
    {
        initLogging();
        m_spCatalog = std::make_unique<api::catalog::Catalog>(getConfig());
    }
    std::unique_ptr<api::catalog::Catalog> m_spCatalog;
};

TEST_P(CatalogGetTest, CatalogCommand)
{
    auto [execution, input, output] = GetParam();
    std::variant<std::string, base::Error> result;
    ASSERT_NO_THROW(result = m_spCatalog->getResource(input, {"ignored"}));
    if (execution == COMMAND_FAILED_CASE)
    {
        ASSERT_TRUE(std::holds_alternative<base::Error>(result));
    }
    else
    {
        ASSERT_TRUE(std::holds_alternative<std::string>(result)) << base::getError(result).message;
        ASSERT_EQ(std::get<std::string>(result), output);
    }
}

INSTANTIATE_TEST_SUITE_P(CatalogCommand,
                         CatalogGetTest,
                         ::testing::Values(std::make_tuple(1, successResourceAssetJson, successJson.str()),
                                           std::make_tuple(2, successCollectionAssetJson, successCollectionJson),
                                           std::make_tuple(3, failResourceAsset, ""),
                                           std::make_tuple(5, successCollectionAssetYml, successCollectionYml)));

class CatalogPostTest : public ::testing::TestWithParam<std::tuple<int, api::catalog::Resource, std::string>>
{
protected:
    void SetUp() override
    {
        initLogging();
        m_spCatalog = std::make_unique<api::catalog::Catalog>(getConfig());
    }
    std::unique_ptr<api::catalog::Catalog> m_spCatalog;
};

TEST_P(CatalogPostTest, CatalogCommand)
{
    auto [execution, input, content] = GetParam();

    std::optional<base::Error> error;
    ASSERT_NO_THROW(error = m_spCatalog->postResource(input, "nsId", content));
    if (execution >= COMMAND_FAILED_CASE)
    {
        ASSERT_TRUE(error);
    }
    else
    {
        ASSERT_FALSE(error);
    }
}

INSTANTIATE_TEST_SUITE_P(CatalogCommand,
                         CatalogPostTest,
                         ::testing::Values(std::make_tuple(1, successCollectionAssetJson, successJson.str()),
                                           std::make_tuple(2, successCollectionAssetYml, successYml),
                                           std::make_tuple(3, successCollectionAssetJson, successYml),
                                           std::make_tuple(4, successResourceAssetJson, successJson.str())));

class CatalogDeleteTest : public ::testing::TestWithParam<std::tuple<int, api::catalog::Resource>>
{
protected:
    void SetUp() override
    {
        initLogging();
        m_spCatalog = std::make_unique<api::catalog::Catalog>(getConfig());
    }
    std::unique_ptr<api::catalog::Catalog> m_spCatalog;
};

TEST_P(CatalogDeleteTest, CatalogCommand)
{
    auto [execution, input] = GetParam();

    std::optional<base::Error> error;
    ASSERT_NO_THROW(error = m_spCatalog->deleteResource(input, {"ignored"}));
    if (execution == COMMAND_FAILED_CASE)
    {
        ASSERT_TRUE(error);
    }
    else
    {
        ASSERT_FALSE(error);
    }
}

INSTANTIATE_TEST_SUITE_P(CatalogCommand,
                         CatalogDeleteTest,
                         ::testing::Values(std::make_tuple(1, successResourceAssetJson),
                                           std::make_tuple(2, successCollectionAssetJson),
                                           std::make_tuple(3, failResourceAsset)));

class CatalogValidateTest : public ::testing::TestWithParam<std::tuple<int, api::catalog::Resource, std::string>>
{
protected:
    void SetUp() override
    {
        initLogging();
        m_spCatalog = std::make_unique<api::catalog::Catalog>(getConfig());
    }
    std::unique_ptr<api::catalog::Catalog> m_spCatalog;
};

TEST_P(CatalogValidateTest, CatalogCommand)
{
    auto [execution, input, content] = GetParam();

    std::optional<base::Error> error;
    ASSERT_NO_THROW(error = m_spCatalog->putResource(input, content));
    if (execution >= COMMAND_FAILED_CASE)
    {
        ASSERT_TRUE(error);
    }
    else
    {
        ASSERT_FALSE(error);
    }
}

INSTANTIATE_TEST_SUITE_P(CatalogCommand,
                         CatalogValidateTest,
                         ::testing::Values(std::make_tuple(1, successResourceAssetJson, successJson.str()),
                                           std::make_tuple(2, successResourceAssetYml, successYml),
                                           std::make_tuple(3, failResourceAsset, successYml),
                                           std::make_tuple(4, successCollectionAssetJson, successJson.str())));
