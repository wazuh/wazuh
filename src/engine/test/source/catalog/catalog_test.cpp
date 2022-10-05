#include <catalog/catalog.hpp>
#include <gtest/gtest.h>

#include <memory>

const base::Name successName {"type.name.ok"};
const base::Name failName {"type.name.fail"};
const json::Json successJson(R"({"key": "value"})");
const std::string successYml(R"(key: value)");
const json::Json validJson(R"({})");
const json::Json invalidJson(R"([])");

class FakeStore : public store::IStore
{
public:
    std::shared_ptr<json::Json> lastAdded;

    ~FakeStore() = default;

    std::variant<json::Json, base::Error> get(const base::Name& name) const override
    {
        if (name.m_version == successName.m_version)
        {
            return successJson;
        }

        return base::Error {"error"};
    }

    std::optional<base::Error> add(const base::Name& name,
                                   const json::Json& content) override
    {
        if (name.m_version == successName.m_version)
        {
            lastAdded = std::make_shared<json::Json>(content);
            return std::nullopt;
        }

        return base::Error {"error"};
    }

    std::optional<base::Error> del(const base::Name& name) override
    {
        if (name.m_version == successName.m_version)
        {
            lastAdded.reset();
            return std::nullopt;
        }

        return base::Error {"error"};
    }
};

class FakeValidator : public builder::IValidator
{
public:
    ~FakeValidator() = default;

    std::optional<base::Error> validateEnvironment(const json::Json& json) const override
    {
        if (json.isObject())
        {
            return std::nullopt;
        }

        return base::Error {"error"};
    }

    std::optional<base::Error> validateAsset(const json::Json& json) const override
    {
        if (json.isObject())
        {
            return std::nullopt;
        }

        return base::Error {"error"};
    }
};

class FakeAPIReg : public IAPIReg
{
};

catalog::Config getConfig()
{
    catalog::Config config;
    config.store = std::make_shared<FakeStore>();
    config.validator = std::make_shared<FakeValidator>();
    config.apiReg = std::make_shared<FakeAPIReg>();
    return config;
}

TEST(CatalogConfigurationTest, Validates)
{
    auto config = getConfig();
    ASSERT_NO_THROW(config.validate());
}

TEST(CatalogConfigurationTest, ValidatesErrorNull)
{
    catalog::Config config;
    config.store = std::make_shared<FakeStore>();
    config.validator = std::make_shared<FakeValidator>();
    config.apiReg = nullptr;
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

TEST(CatalogTest, JsonGet)
{
    auto config = getConfig();
    catalog::Catalog catalog(config);
    std::variant<std::string, base::Error> result;
    auto name = successName;
    name.m_type = catalog::typeToString(catalog::Type::DECODER);
    ASSERT_NO_THROW(result = catalog.get(name, catalog::Format::JSON));
    ASSERT_TRUE(std::holds_alternative<std::string>(result));
    ASSERT_EQ(std::get<std::string>(result), successJson.str());
}

TEST(CatalogTest, YmlGet)
{
    auto config = getConfig();
    catalog::Catalog catalog(config);
    std::variant<std::string, base::Error> result;
    auto name = successName;
    name.m_type = catalog::typeToString(catalog::Type::DECODER);
    ASSERT_NO_THROW(result = catalog.get(name, catalog::Format::YAML));
    ASSERT_TRUE(std::holds_alternative<std::string>(result));
    ASSERT_EQ(std::get<std::string>(result), successYml);
}

TEST(CatalogTest, GetNotSupportedType)
{
    auto config = getConfig();
    catalog::Catalog catalog(config);
    std::variant<std::string, base::Error> result;
    auto name = successName;
    name.m_type = "not_supported";
    ASSERT_NO_THROW(result = catalog.get(name, catalog::Format::JSON));
    ASSERT_TRUE(std::holds_alternative<base::Error>(result));
}

TEST(CatalogTest, GetDriverError)
{
    auto config = getConfig();
    catalog::Catalog catalog(config);
    std::variant<std::string, base::Error> result;
    auto name = failName;
    name.m_type = catalog::typeToString(catalog::Type::DECODER);
    ASSERT_NO_THROW(result = catalog.get(name, catalog::Format::JSON));
    ASSERT_TRUE(std::holds_alternative<base::Error>(result));
}

TEST(CatalogTest, JsonAdd)
{
    auto config = getConfig();
    catalog::Catalog catalog(config);
    std::optional<base::Error> error;
    auto name = successName;
    name.m_type = catalog::typeToString(catalog::Type::DECODER);
    ASSERT_NO_THROW(error = catalog.add(name, successJson.str(), catalog::Format::JSON));
    ASSERT_FALSE(error);
    ASSERT_TRUE(std::reinterpret_pointer_cast<FakeStore>(config.store)->lastAdded.get());
    ASSERT_EQ(*std::static_pointer_cast<FakeStore>(config.store)->lastAdded, successJson);
}

TEST(CatalogTest, YmlAdd)
{
    auto config = getConfig();
    catalog::Catalog catalog(config);
    std::optional<base::Error> error;
    auto name = successName;
    name.m_type = catalog::typeToString(catalog::Type::DECODER);
    ASSERT_NO_THROW(error = catalog.add(name, successYml, catalog::Format::YAML));
    ASSERT_FALSE(error);
    ASSERT_TRUE(std::reinterpret_pointer_cast<FakeStore>(config.store)->lastAdded);
    ASSERT_EQ(*std::static_pointer_cast<FakeStore>(config.store)->lastAdded, successJson);
}

TEST(CatalogTest, AddNotSupportedType)
{
    auto config = getConfig();
    catalog::Catalog catalog(config);
    std::optional<base::Error> error;
    auto name = successName;
    name.m_type = "not_supported";
    ASSERT_NO_THROW(error = catalog.add(name, successJson.str(), catalog::Format::JSON));
    ASSERT_TRUE(error);
}

TEST(CatalogTest, AddDriverError)
{
    auto config = getConfig();
    catalog::Catalog catalog(config);
    std::optional<base::Error> error;
    auto name = failName;
    name.m_type = catalog::typeToString(catalog::Type::DECODER);
    ASSERT_NO_THROW(error = catalog.add(name, successJson.str(), catalog::Format::JSON));
    ASSERT_TRUE(error);
}

TEST(CatalogTest, Del)
{
    auto config = getConfig();
    catalog::Catalog catalog(config);
    std::optional<base::Error> error;
    auto name = successName;
    name.m_type = catalog::typeToString(catalog::Type::DECODER);
    ASSERT_NO_THROW(error = catalog.del(name));
    ASSERT_FALSE(error);
}

TEST(CatalogTest, DelNotSupportedType)
{
    auto config = getConfig();
    catalog::Catalog catalog(config);
    std::optional<base::Error> error;
    auto name = successName;
    name.m_type = "not_supported";
    ASSERT_NO_THROW(error = catalog.del(name));
    ASSERT_TRUE(error);
}

TEST(CatalogTest, DelDriverError)
{
    auto config = getConfig();
    catalog::Catalog catalog(config);
    std::optional<base::Error> error;
    auto name = failName;
    name.m_type = catalog::typeToString(catalog::Type::DECODER);
    ASSERT_NO_THROW(error = catalog.del(name));
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
