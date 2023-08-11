#ifndef RNM_IRESOURCE_NAMESPACE_MANAGER_HPP
#define RNM_IRESOURCE_NAMESPACE_MANAGER_HPP

#include "iCatalogStore.hpp"
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
