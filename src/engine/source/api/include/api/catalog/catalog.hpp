#ifndef _CATALOG_HPP
#define _CATALOG_HPP

#include <functional>
#include <memory>
#include <optional>
#include <unordered_map>
#include <variant>

#include <builder/ivalidator.hpp>
#include <error.hpp>
#include <name.hpp>
#include <store/istore.hpp>

namespace api::catalog
{

/**
 * @brief Catalog configuration.
 *
 */
struct Config
{
    /* store interface to manipulate the Asset, Environment and Schema files */
    std::shared_ptr<store::IStore> store;
    /* Validator interface to validate the Asset, Environment and Schema files */
    std::shared_ptr<builder::IValidator> validator;

    /**
     * @brief Assert that the configuration is valid.
     *
     */
    void validate() const;
};

/**
 * @brief Supported formats by the catalog
 *
 */
enum class Format
{
    JSON,
    YAML,
    ERROR_FORMAT
};

/**
 * @brief Get string representation of the Format
 *
 * @param format Format to convert
 * @return constexpr auto String representation of the format
 */
constexpr auto formatToString(Format format)
{
    switch (format)
    {
        case Format::JSON: return "json";
        case Format::YAML: return "yaml";
        default: return "error_format";
    }
}

/**
 * @brief Get Format from string representation
 *
 * @param format String representation of the format
 * @return Format
 */
static const auto stringToFormat(const std::string& format)
{
    if (format == "json")
    {
        return Format::JSON;
    }
    else if (format == "yaml")
    {
        return Format::YAML;
    }
    else
    {
        return Format::ERROR_FORMAT;
    }
}

/**
 * @brief Type of the resources handled by the catalog
 *
 */
enum class Type
{
    DECODER,
    RULE,
    OUTPUT,
    FILTER,
    SCHEMA,
    ENVIRONMENT,
    ERROR_TYPE
};

/**
 * @brief Get string representation of the Type
 *
 * @param type Type to convert
 * @return constexpr auto String representation of the type
 */
constexpr auto typeToString(Type type)
{
    switch (type)
    {
        case Type::DECODER: return "decoder";
        case Type::RULE: return "rule";
        case Type::OUTPUT: return "output";
        case Type::FILTER: return "filter";
        case Type::SCHEMA: return "schema";
        case Type::ENVIRONMENT: return "environment";
        default: return "error_type";
    }
}

/**
 * @brief Get the Type from the string representation
 *
 * @param type String representation of the type
 * @return const auto Type
 */
constexpr auto stringToType(const char* type)
{
    if (type == typeToString(Type::DECODER))
        return Type::DECODER;
    else if (type == typeToString(Type::RULE))
        return Type::RULE;
    else if (type == typeToString(Type::OUTPUT))
        return Type::OUTPUT;
    else if (type == typeToString(Type::FILTER))
        return Type::FILTER;
    else if (type == typeToString(Type::SCHEMA))
        return Type::SCHEMA;
    else if (type == typeToString(Type::ENVIRONMENT))
        return Type::ENVIRONMENT;
    else
        return Type::ERROR_TYPE;
}

class CatalogName : public base::Name
{
public:
    constexpr static auto MAX_PARTS = 3;

    CatalogName() = default;

    CatalogName(std::string type, std::string name, std::string version)
        : base::Name({type, name, version})
    {
    }

    CatalogName(const std::string& name)
        : base::Name{name}
    {
    }

    CatalogName(const char* name)
        : base::Name{name}
    {
    }

    std::string type() const
    {
        return parts()[0];
    }

    std::string name() const
    {
        return parts()[1];
    }

    std::string version() const
    {
        return parts()[2];
    }
};

/**
 * @brief Public interface to handle the manipulation of the Assets, Environments and
 * Schemas.
 *
 * Exposes:
 *  - Asset, Environment and Schema manipulation.
 *  - Asset, Environment and Schema validation.
 *  - Type conversion of Environment and Assets.
 *  - API handlers.
 */
class Catalog
{
    // TODO: Add schema to asset validation
private:
    std::shared_ptr<store::IStore> m_store;
    std::shared_ptr<builder::IValidator> m_validator;

    std::unordered_map<
        Format,
        std::function<std::variant<std::string, base::Error>(const json::Json&)>>
        m_outFormat;
    std::unordered_map<
        Format,
        std::function<std::variant<json::Json, base::Error>(const std::string&)>>
        m_inFormat;

public:
    /**
     * @brief Construct a new Catalog object
     *
     * @param config Catalog configuration
     * @throw std::runtime_error If could not initialize the catalog
     */
    Catalog(const Config& config);
    ~Catalog() = default;

    Catalog(const Catalog&) = delete;
    Catalog& operator=(const Catalog&) = delete;

    /**
     * @brief Get the Asset object
     *
     * @param name Name of the Asset
     * @param format Output format of the Asset
     * @return std::variant<std::string, base::Error> Asset in the requested format
     * string, or error
     */
    std::variant<std::string, base::Error> getAsset(const CatalogName& name,
                                                    Format format) const;

    /**
     * @brief Add an Asset to the catalog
     *
     * @param name Name of the Asset
     * @param content Asset as string, in the format specified
     * @param format Format of the Asset
     * @return std::optional<base::Error> Error if the Asset could not be added
     */
    std::optional<base::Error>
    addAsset(const CatalogName& name, const std::string& content, Format format);

    /**
     * @brief Delete an Asset from the catalog
     *
     * @param name Name of the Asset
     * @return std::optional<base::Error> Error if the Asset could not be deleted
     */
    std::optional<base::Error> delAsset(const CatalogName& name);

    /**
     * @brief Validate an Environment
     *
     * @param environment Environment to validate
     * @return std::optional<base::Error> Error if the Environment is not valid
     */
    std::optional<base::Error> validateEnvironment(const json::Json& environment) const;

    /**
     * @brief Validate an Asset
     *
     * @param asset Asset to validate
     * @return std::optional<base::Error> Error if the Asset is not valid
     */
    std::optional<base::Error> validateAsset(const json::Json& asset) const;
};

} // namespace api::catalog
#endif // _CATALOG_HPP
