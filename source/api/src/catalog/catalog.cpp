#include "api/catalog/catalog.hpp"

#include <fmt/format.h>

#include "yml2Json.hpp"

namespace api::catalog
{
void Config::validate() const
{
    if (!store)
    {
        throw std::runtime_error("[Catalog::Config] Store is not set");
    }
    if (!validator)
    {
        throw std::runtime_error("[Catalog::Config] Validator is not set");
    }
}

Catalog::Catalog(const Config& config)
{
    config.validate();
    m_store = config.store;
    m_validator = config.validator;

    // Json handling
    m_outFormat[Format::JSON] = [](const json::Json& json)
    {
        return json.str();
    };
    m_inFormat[Format::JSON] = [](const std::string& str)
    {
        std::variant<json::Json, base::Error> result;
        try
        {
            result = json::Json {str.c_str()};
        }
        catch (const std::exception& e)
        {
            result = base::Error {e.what()};
        }

        return result;
    };

    // Yaml handling
    m_outFormat[Format::YAML] = [](const json::Json& json)
    {
        std::variant<std::string, base::Error> result;
        try
        {
            // TODO: Expose internals on json::Json ??
            rapidjson::Document doc;
            doc.Parse(json.str().c_str());
            auto yaml = yml2json::internal::json2yaml(doc);
            YAML::Emitter out;
            out << yaml;
            result = out.c_str();
        }
        catch (const std::exception& e)
        {
            result = base::Error {e.what()};
        }

        return result;
    };
    m_inFormat[Format::YAML] = [](const std::string& str)
    {
        std::variant<json::Json, base::Error> result;
        try
        {
            result = json::Json {yml2json::loadYMLfromString(str)};
        }
        catch (const std::exception& e)
        {
            result = base::Error {e.what()};
        }

        return result;
    };
}

std::variant<std::string, base::Error> Catalog::getAsset(const CatalogName& name,
                                                         Format format) const
{
    auto type = stringToType(name.type().c_str());
    if (type == Type::ERROR_TYPE)
    {
        return base::Error {
            fmt::format("[Catalog::getAsset] Invalid type [{}]", name.type())};
    }

    if (type != Type::DECODER && type != Type::RULE && type != Type::FILTER
        && type != Type::OUTPUT)
    {
        return base::Error {
            fmt::format("[Catalog::getAsset] Not asset type [{}]", name.type())};
    }

    auto outFormat = m_outFormat.find(format);
    if (outFormat == m_outFormat.end())
    {
        return base::Error {fmt::format(
            "[Catalog::getAsset] Format [{}] is not supported", formatToString(format))};
    }

    auto content = m_store->get(name);
    if (std::holds_alternative<base::Error>(content))
    {
        return base::Error {fmt::format("[Catalog::getAsset] Cannot get [{}], {}",
                                        name.fullName(),
                                        std::get<base::Error>(content).message)};
    }

    // TODO: Validate content depending on type
    auto contentJson = std::move(std::get<json::Json>(content));

    auto formatResult = outFormat->second(contentJson);
    if (std::holds_alternative<base::Error>(formatResult))
    {
        return base::Error {
            fmt::format("[Catalog::getAsset] Cannot format to type [{}], {}",
                        formatToString(format),
                        std::get<base::Error>(formatResult).message)};
    }

    return std::get<std::string>(formatResult);
}

std::optional<base::Error>
Catalog::addAsset(const CatalogName& name, const std::string& content, Format format)
{
    auto type = stringToType(name.type().c_str());
    if (type == Type::ERROR_TYPE)
    {
        return base::Error {fmt::format("[Catalog::add] Invalid type [{}]", name.type())};
    }

    if (type != Type::DECODER && type != Type::RULE && type != Type::FILTER
        && type != Type::OUTPUT)
    {
        return base::Error {
            fmt::format("[Catalog::add] Not asset type [{}]", name.type())};
    }

    auto inFormat = m_inFormat.find(format);
    if (inFormat == m_inFormat.end())
    {
        return base::Error {fmt::format("[Catalog::add] Format [{}] is not supported",
                                        formatToString(format))};
    }

    auto json = inFormat->second(content);
    if (std::holds_alternative<base::Error>(json))
    {
        return base::Error {
            fmt::format("[Catalog::add] Cannot transform type [{}] to JSON, {}",
                        formatToString(format),
                        std::get<base::Error>(json).message)};
    }
    auto strJson = std::get<json::Json>(json).str();
    // TODO: Validate content depending on type
    auto contentJson = std::move(std::get<json::Json>(json));

    auto error = m_store->add(name, contentJson);
    if (error)
    {
        return base::Error {fmt::format("[Catalog::add] Cannot add [{}], {}",
                                        name.fullName(),
                                        error.value().message)};
    }

    return std::nullopt;
}

std::optional<base::Error> Catalog::delAsset(const CatalogName& name)
{
    auto type = stringToType(name.type().c_str());
    if (type == Type::ERROR_TYPE)
    {
        return base::Error {fmt::format("[Catalog::del] Invalid type [{}]", name.type())};
    }

    if (type != Type::DECODER && type != Type::RULE && type != Type::FILTER
        && type != Type::OUTPUT)
    {
        return base::Error {
            fmt::format("[Catalog::del] Not asset type [{}]", name.type())};
    }

    auto error = m_store->del(name);
    if (error)
    {
        return base::Error {fmt::format("[Catalog::del] Cannot delete [{}], {}",
                                        name.fullName(),
                                        error.value().message)};
    }

    return std::nullopt;
}

std::optional<base::Error>
Catalog::validateEnvironment(const json::Json& environment) const
{
    // TODO: Validate against appropriate schema first

    std::optional<base::Error> error;
    error = m_validator->validateEnvironment(environment);
    if (error)
    {
        return base::Error {
            fmt::format("[Catalog::validateEnvironment] Validation failed, {}",
                        error.value().message)};
    }

    return std::nullopt;
}

std::optional<base::Error> Catalog::validateAsset(const json::Json& asset) const
{
    // TODO: Validate against appropriate schema first

    std::optional<base::Error> error;
    error = m_validator->validateAsset(asset);
    if (error)
    {
        return base::Error {fmt::format("[Catalog::validateAsset] Validation failed, {}",
                                        error.value().message)};
    }

    return std::nullopt;
}
} // namespace api::catalog
