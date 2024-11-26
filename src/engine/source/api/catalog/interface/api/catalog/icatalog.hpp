#ifndef __API_CATALOG_ICATALOG_HPP
#define __API_CATALOG_ICATALOG_HPP

#include <api/catalog/resource.hpp>
#include <base/error.hpp>
#include <store/istore.hpp>

namespace api::catalog
{

class ICatalog
{
public:
    virtual ~ICatalog() = default;

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
    virtual base::OptError
    postResource(const Resource& collection, const std::string& namespaceStr, const std::string& content) = 0;

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
    virtual base::OptError
    putResource(const Resource& item, const std::string& content, const std::string& namespaceId) = 0;

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
    virtual base::RespOrError<std::string> getResource(const Resource& resource,
                                                       const std::string& namespaceId) const = 0;

    /**
     * @brief Delete a resource
     *
     * @param resource Resource identifying the item or collection to delete
     * @param namespaceId Namespace name where the items are located, only needed if resource is a collection
     * @return std::optional<base::Error> Error if the operation failed
     */
    virtual base::OptError deleteResource(const Resource& resource, const std::string& namespaceId) = 0;

    /**
     * @brief Validate an Asset
     *
     * Performs schema validation and builder validation
     *
     * @param item Resource identifying an Asset
     * @param content Content of the Asset or Environment
     * @return std::optional<base::Error> Error if the operation failed
     */
    virtual base::OptError
    validateResource(const Resource& item, const std::string& namespaceId, const std::string& content) const = 0;

    /**
     * @brief Get all namespaces
     *
     * @return std::vector<store::NamespaceId> List of all namespaces
     */
    virtual std::vector<store::NamespaceId> getAllNamespaces() const = 0;
};
} // namespace api::catalog

#endif // __API_CATALOG_ICATALOG_HPP
