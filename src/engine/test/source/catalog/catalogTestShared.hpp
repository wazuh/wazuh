#ifndef _CATALOG_TEST_SHARED_HPP
#define _CATALOG_TEST_SHARED_HPP

#include <memory>

#include <catalog/catalog.hpp>

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

inline catalog::Config getConfig()
{
    catalog::Config config;
    config.store = std::make_shared<FakeStore>();
    config.validator = std::make_shared<FakeValidator>();
    return config;
}

#endif // _CATALOG_TEST_SHARED_HPP
