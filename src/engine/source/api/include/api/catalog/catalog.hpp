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
#include <base/error.hpp>
#include <base/name.hpp>
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

    std::optional<base::Error> validate(const Resource& item, const std::string& namespaceId, const json::Json& content) const;

    /**
     * @brief Get the Document or error from the store.
     *
     * @param resource Resource identifying the document
     * @return base::RespOrError<store::Doc> Document or error
     */
    base::RespOrError<store::Doc> getDoc(const Resource& resource) const;

    /**
     * @brief Get a collection or error from the store.
     *
     * @param resource Resource identifying the collection
     * @param namespaceId Namespace name where the collection search
     * @return base::RespOrError<store::Col>
     */
    base::RespOrError<store::Col> getCol(const Resource& resource, const std::string& namespaceId) const;

    /**
     * @brief Delete a document or error from the store.
     *
     * @param resource Resource identifying the document
     * @return base::OptError Error if the operation failed
     */
    base::OptError delDoc(const Resource& resource);

    /**
     * @brief Delete a collection or error from the store.
     *
     * @param resource Resource identifying the collection
     * @param namespaceId Namespace name where the collection is located
     * @return base::OptError Error if the operation failed
     */
    base::OptError delCol(const Resource& resource, const std::string& namespaceId);

    /**
     * @brief Checks if a resource exists in a specified namespace before performing a given operation.
     *
     * This function is designed to be a common utility for checking the existence of a resource in a namespace
     * before carrying out operations like get, put, or delete.
     *
     * @param item The resource to be checked.
     * @param namespaceId The identifier of the namespace in which to check for the resource.
     * @param operation A description of the operation to be performed (e.g., "get", "put", "delete").
     * @return An optional containing an Error if the resource check fails, or std::nullopt if the check is successful.
     */
    std::optional<base::Error> checkResourceInNamespace(const api::catalog::Resource& item,
                                                        const std::string& namespaceId,
                                                        const std::string& operation) const;

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
     * @param namespaceId Namespace name where the items are located, only needed if resource is a collection
     * @return std::optional<base::Error>
     */
    std::optional<base::Error>
    putResource(const Resource& item, const std::string& content, const std::string& namespaceId);

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
     * @param namespaceId Namespace name where the items are located, only needed if resource is a collection
     * @return base::RespOrError<std::string> Error if the operation failed or the
     * content of the resource
     */
    base::RespOrError<std::string> getResource(const Resource& resource, const std::string& namespaceId) const;

    /**
     * @brief Delete a resource
     *
     * @param resource Resource identifying the item or collection to delete
     * @param namespaceId Namespace name where the items are located, only needed if resource is a collection
     * @return std::optional<base::Error> Error if the operation failed
     */
    base::OptError deleteResource(const Resource& resource, const std::string& namespaceId);

    /**
     * @brief Validate an Asset
     *
     * Performs schema validation and builder validation
     *
     * @param item Resource identifying an Asset
     * @param content Content of the Asset or Environment
     * @return std::optional<base::Error> Error if the operation failed
     */
    std::optional<base::Error>
    validateResource(const Resource& item, const std::string& namespaceId, const std::string& content) const;

    /**
     * @brief Get the All Namespaces object
     *
     * @return std::vector<store::NamespaceId>
     */
    inline std::vector<store::NamespaceId> getAllNamespaces() const { return m_store->listNamespaces(); }
};

} // namespace api::catalog
#endif // _CATALOG_HPP
