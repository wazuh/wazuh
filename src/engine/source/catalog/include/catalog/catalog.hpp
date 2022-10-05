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

// TODO: Remove once API interface is properly defined
class IAPIReg
{
};

namespace catalog
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
    /* API interface, to handle the API calls */
    std::shared_ptr<IAPIReg> apiReg;

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
    YAML
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
        default: return "unknown";
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
static const auto stringToType(const std::string& type)
{
    if (type == "decoder")
        return Type::DECODER;
    if (type == "rule")
        return Type::RULE;
    if (type == "output")
        return Type::OUTPUT;
    if (type == "filter")
        return Type::FILTER;
    if (type == "schema")
        return Type::SCHEMA;
    if (type == "environment")
        return Type::ENVIRONMENT;
    return Type::ERROR_TYPE;
}

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
    std::shared_ptr<IAPIReg> m_apiReg;

    std::unordered_map<
        Format,
        std::function<std::variant<std::string, base::Error>(const json::Json&)>>
        m_outFormat;
    std::unordered_map<
        Format,
        std::function<std::variant<json::Json, base::Error>(const std::string&)>>
        m_inFormat;

public:
    Catalog(const Config& config);
    ~Catalog() = default;

    Catalog(const Catalog&) = delete;
    Catalog& operator=(const Catalog&) = delete;

    std::variant<std::string, base::Error> get(const base::Name& name,
                                               Format format) const;
    std::optional<base::Error>
    add(const base::Name& name, const std::string& content, Format format);
    std::optional<base::Error> del(const base::Name& name);

    std::optional<base::Error> validateEnvironment(const json::Json& environment) const;
    std::optional<base::Error> validateAsset(const json::Json& asset) const;
};

} // namespace catalog
#endif // _CATALOG_HPP
