#ifndef _CATALOG_TEST_SHARED_HPP
#define _CATALOG_TEST_SHARED_HPP

#include <memory>

#include <fmt/format.h>

#include <api/catalog/catalog.hpp>

const base::Name successName({"decoder", "name", "ok"});
const base::Name failName {{"decoder", "name", "fail"}};
const json::Json
    successJson(fmt::format("{{\"name\": \"{}\"}}", successName.fullName()).c_str());
const json::Json
    successCollectionJson(fmt::format("[\"{}\"]", successName.fullName()).c_str());
const std::string successYml(fmt::format("name: {}", successName.fullName()).c_str());
const std::string successCollectionYml(fmt::format("- {}", successName.fullName()));
const json::Json validJson(R"({})");
const json::Json invalidJson(R"([])");
const std::string schema {R"({"type": "object"})"};
const base::Name successSchemaName({"schema", "name", "ok"});
const base::Name failSchemaName({"schema", "name", "fail"});

const api::catalog::Resource successResourceAssetJson {
    base::Name({api::catalog::Resource::typeToStr(api::catalog::Resource::Type::decoder),
                successName.parts()[1],
                successName.parts()[2]}),
    api::catalog::Resource::Format::json};

const api::catalog::Resource successResourceAssetYml {
    base::Name({api::catalog::Resource::typeToStr(api::catalog::Resource::Type::decoder),
                successName.parts()[1],
                successName.parts()[2]}),
    api::catalog::Resource::Format::yaml};

const api::catalog::Resource failResourceAsset {
    base::Name({api::catalog::Resource::typeToStr(api::catalog::Resource::Type::decoder),
                failName.parts()[1],
                failName.parts()[2]}),
    api::catalog::Resource::Format::json};

const api::catalog::Resource successCollectionAssetJson {
    base::Name(
        {api::catalog::Resource::typeToStr(api::catalog::Resource::Type::decoder)}),
    api::catalog::Resource::Format::json};

const api::catalog::Resource successCollectionAssetYml {
    base::Name(
        {api::catalog::Resource::typeToStr(api::catalog::Resource::Type::decoder)}),
    api::catalog::Resource::Format::yaml};

class FakeStore : public store::IStore
{
public:
    std::shared_ptr<json::Json> lastAdded;

    ~FakeStore() = default;

    std::variant<json::Json, base::Error> get(const base::Name& name) const override
    {
        if (name.parts()[2] == successName.parts()[2])
        {
            return successJson;
        }
        if (name == successCollectionAssetJson.m_name)
        {
            return successCollectionJson;
        }

        return base::Error {"error"};
    }

    std::optional<base::Error> add(const base::Name& name,
                                   const json::Json& content) override
    {
        if (name.parts()[2] == successName.parts()[2])
        {
            lastAdded = std::make_shared<json::Json>(content);
            return std::nullopt;
        }

        return base::Error {"error"};
    }

    std::optional<base::Error> del(const base::Name& name) override
    {
        if (name.parts()[2] == successName.parts()[2])
        {
            lastAdded.reset();
            return std::nullopt;
        }

        if (name == successCollectionAssetJson.m_name)
        {
            lastAdded.reset();
            return std::nullopt;
        }

        return base::Error {"error"};
    }

    std::optional<base::Error> update(const base::Name& name,
                                      const json::Json& content) override
    {
        if (name.parts()[2] == successName.parts()[2])
        {
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

inline api::catalog::Config getConfig(bool schemaOk = true)
{
    api::catalog::Config config;
    config.store = std::make_shared<FakeStore>();
    config.validator = std::make_shared<FakeValidator>();

    if (schemaOk)
    {
        config.assetSchema = successSchemaName.fullName();
        config.environmentSchema = successSchemaName.fullName();
    }
    else
    {
        config.assetSchema = failSchemaName.fullName();
        config.environmentSchema = failSchemaName.fullName();
    }

    return config;
}

#endif // _CATALOG_TEST_SHARED_HPP
