#ifndef RNM_IRESOURCE_NAMESPACE_MANAGER_HPP
#define RNM_IRESOURCE_NAMESPACE_MANAGER_HPP

#include <memory>
#include <optional>
#include <string>
#include <variant>

#include <json/json.hpp>
#include <store/istore.hpp>

#include "resourceAccessDef.h"

/**
 * @brief Resource Namespace Manager Interface
 *
 * Manages the resource namespaces, which are used to group resources together
 * and to assign roles to them. (Permissions and visibility)
 * The resource name are unique regardless of the namespace.
 * The namespace is used to group resources together, a resource must be assigned to a namespace.
 *
 */
namespace rnm
{

/**
 * @brief Resource Store Reader Interface
 *
 */
class ICatalogStoreReader
{
protected:
    ICatalogStoreReader() = default;

public:
    /**
     * @brief Get the Virual Space Name where the resource belongs to.
     *
     * @param resourceName of the resource.
     * @return The Virtual Space Name or an empty optional if the resource does not exist or is a collection.
     */
    virtual std::optional<VSName> getVSName(const base::Name& resourceName) const = 0;

    /**
     * @brief Get a json from the store, using the role for checking permissions and visibility.
     *
     * @param item Resource name or collection name to obtain.
     * @param role Role name to perform the operation.
     * @return std::variant<json::Json, base::Error> The json or an error.
     */
    virtual std::variant<json::Json, base::Error> get(const base::Name& item, const RoleName& role) const = 0;
};

/**
 * @brief Resource Store Interface
 *
 */
class ICatalogStore : public ICatalogStoreReader
{
protected:
    ICatalogStore() = default;

public:
    /**
     * @brief Add a json to the store.
     *
     * @param resourceName base::Name of the json to add.
     * @param content Json to add.
     * @param role Role name of the json to get.
     * @return std::optional<base::Error> An error if the operation failed.
     */
    virtual std::optional<base::Error>
    add(const base::Name& resourceName, const json::Json& content, const VSName& vsname, const RoleName& role) = 0;

    /**
     * @brief Delete a json from the store.
     *
     * @param resourceName base::Name of the json to delete.
     * @return std::optional<base::Error> An error if the operation failed.
     */
    virtual std::optional<base::Error> del(const base::Name& resourceName, const RoleName& role) = 0;

    /**
     * @brief Update a json in the store.
     *
     * @param resourceName
     * @param content Json to update.
     * @return std::optional<base::Error> An error if the operation failed.
     */
    virtual std::optional<base::Error>
    update(const base::Name& resourceName, const json::Json& content, const RoleName& role) = 0;

    /**
     * @brief Change the Virtual Space Name where the resource belongs to.
     *
     * @param resourceName Name of the resource.
     * @param vsname   The Virtual Space Name.
     * @param role Role name to perform the operation,  should has write permission on both the old and new Virtual
     * Space Name.
     * @return std::optional<base::Error> An error if the operation failed.
     */
    virtual std::optional<base::Error>
    setVSName(const base::Name& resourceName, const VSName& vsname, const RoleName& role) = 0;

    /* Cast operators
    operator ICatalogStoreReader() const = 0;
    operator ICatalogStoreReader() const {
         return ICatalogStoreReader(*this);
    }
    */
};

/**
 * @brief Resource Namespace Manager Interface
 *
 */
class IResourceNamespaceManager : public ICatalogStore
{

public:
    virtual ~IResourceNamespaceManager() = default;

    /* Cast operators
    operator ICatalogStore() const = 0;
    operator ICatalogStore() const {
         return ICatalogStore(*this);
    }
    */
};

} // namespace rnm

#endif // RNM_IRESOURCE_NAMESPACE_MANAGER_HPP
