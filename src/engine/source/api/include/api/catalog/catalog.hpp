#ifndef _CATALOG_HPP
#define _CATALOG_HPP

#include <cstring>
#include <exception>
#include <functional>
#include <memory>
#include <optional>
#include <unordered_map>
#include <variant>

#include <fmt/format.h>

#include <api/catalog/resource.hpp>
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
    /* Name of the schema to validate assets */
    std::string assetSchema;
    /* Name of the schema to validate environments */
    std::string environmentSchema;

    /**
     * @brief Assert that the configuration is valid.
     *
     */
    void validate() const;
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

    std::unordered_map<Resource::Format, std::function<std::variant<std::string, base::Error>(const json::Json&)>>
        m_outFormat;
    std::unordered_map<Resource::Format, std::function<std::variant<json::Json, base::Error>(const std::string&)>>
        m_inFormat;

    std::unordered_map<Resource::Type, json::Json> m_schemas;

    std::optional<base::Error> validate(const Resource& item, const json::Json& content) const;

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
     * @brief Add and item to the specified collection
     *
     * @param collection Resource identifying the collection, the name must be the same as
     * the type of the name content and the content must be a string in the same format as
     * the collection.m_format
     * @param namespaceStr Namespace name where the item will be added
     * @param content String with the resource to add to the collection.
     * @return std::optional<base::Error> Error if the operation failed
     */
    std::optional<base::Error>
    postResource(const Resource& collection, const std::string& namespaceStr, const std::string& content);

    /**
     * @brief Update an item
     *
     * @param resource Resource identifying the item to update, the name must be the same
     * as the content name and the content must be a string in the same format as the
     * resource.m_format
     * @param content String with the resource to update the item.
     * @return std::optional<base::Error>
     */
    std::optional<base::Error> putResource(const Resource& item, const std::string& content);

    /**
     * @brief Get a resource
     *
     * If the resource is a collection, the content will be a list of the items.
     * If the resource is an item, the content will be the item.
     *
     * In both cases the content will be a string formatted in the same format as the
     * resource.m_format
     *
     * @param resource Resource identifying the item or collection to get
     * @return std::variant<std::string, base::Error> Error if the operation failed or the
     * content of the resource
     */
    std::variant<std::string, base::Error> getResource(const Resource& resource) const;

    /**
     * @brief Delete a resource
     *
     * @param resource Resource identifying the item or collection to delete
     * @return std::optional<base::Error> Error if the operation failed
     */
    std::optional<base::Error> deleteResource(const Resource& resource);

    /**
     * @brief Validate an Asset or Environment.
     *
     * Performs schema validation and builder validation
     *
     * @param item Resource identifying an Asset or Environment
     * @param content Content of the Asset or Environment
     * @return std::optional<base::Error> Error if the operation failed
     */
    std::optional<base::Error> validateResource(const Resource& item, const std::string& content) const;
};

} // namespace api::catalog
#endif // _CATALOG_HPP
