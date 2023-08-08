#ifndef _VIRTUALSPACE_IVIRTUALSPACE_HPP
#define _VIRTUALSPACE_IVIRTUALSPACE_HPP

#include <string>
#include <tuple>
#include <unordered_set>
#include <vector>

/**
 * @brief
 *
 */
namespace virtualspace
{

/**
 * @brief The subcomponents of the virtual space.
 *
 * Each component is a separate namespace for the virtual space. This prevents name collisions
 * between components (Asset "A" in component catalog is different from "A" in component KVDB).
 *
 * In the future, this will be used to allow assign virtual names to rutes, session test etc (?)
 */
enum class Component
{
    CATALOG,
    KVDB,
};

/**
 * @brief The operations that can be performed on the virtual space.
 * CRUD operations are supported (?)
 */
enum class Operation
{
    CREATE,
    READ,
    UPDATE,
    DELETE,
};

/**
 * @brief Resource is a tuple of the sub-resource path and the component it belongs to.
 * - {KVDB, "mydb"}
 * - {CATALOG, "filter/allow/0"}
 * The resource belong to a virtual space.
 */
class Resource
{
private:
    Component component;
    std::string str;

public:
    Resource(Component c, const std::string& s)
        : component(c)
        , str(s)
    {
    }

    Component getComponent() const { return component; }
    const std::string& getString() const { return str; }

    bool operator==(const Resource& other) const { return component == other.component && str == other.str; }
};

/**
 * @brief Role is a string that identifies a role in the virtual space.
 */
using Role = std::string_view;

/**
 * @brief Virtual Space Name is a string that identifies a virtual space.
 */
using VSName = std::string_view;

/**
 * @brief The Virtual Space interface. This is used to manage one virtual space.
 *
 */
class IVirtualSpaceManager
{
public:
    virtual ~IVirtualSpaceManager() = default;

    /**************************************************************************
     *                  Virtual Spaces Management
     **************************************************************************/

    /**
     * @brief Add a new namespace to the virtual spaces
     *
     * @param name Name of the namespace
     * @return true If the namespace was added successfully. False otherwise.
     */
    virtual bool addNamespace(const VSName& name) = 0;

    /**
     * @brief Remove a namespace from the virtual spaces
     *
     * @param name Name of the namespace
     * @return true If the namespace was removed successfully. False otherwise.
     */
    virtual bool removeNamespace(const VSName& name) = 0;

    /**
     * @brief Get the Namespaces object of the virtual spaces
     *
     * @return std::unordered_set<VSName> Namespaces of the virtual spaces
     */
    virtual std::unordered_set<VSName> getNamespaces() const = 0;

    /**************************************************************************
     *                       Resources Management
     **************************************************************************/
    /**
     * @brief Add a resource to a namespace
     *
     * @param vsName Name of the namespace
     * @param res Resource to add
     * @return true If the resource was added successfully. False otherwise.
     */
    virtual bool addResourceToNamespace(const VSName& vsName, const Resource& res) = 0;

    /**
     * @brief Remove a resource from a namespace (if it exists)
     *
     * @param vsName Name of the namespace
     * @param res Resource to remove (if it exists)
     */
    virtual void removeResourceFromNamespace(const VSName& vsName, const Resource& res) = 0;

    /**
     * @brief Get the Resources In Namespace object
     *
     * @param vsName Name of the namespace
     * @return std::unordered_set<Resource>
     */
    virtual std::unordered_set<Resource> getResourcesInNamespace(const VSName& vsName) const = 0;

    /**************************************************************************
     *                       Roles Management
     **************************************************************************/
    /**
     * @brief Add a role to the virtual space
     * @param name Name of the role
     * @return true If the role was added successfully. False otherwise.
     */
    virtual bool addRole(const Role& name) = 0;

    /**
     * @brief Remove a role from the virtual space
     * @param name Name of the role
     * @return true If the role was removed successfully. False otherwise.
     */
    virtual bool removeRole(const Role& name) = 0;

    /**
     * @brief Get the Roles object
     *
     * @return std::unordered_set<Role> Roles of the virtual space
     */
    virtual std::unordered_set<Role> getRoles() const = 0;

    /**************************************************************************
     *                       Permissions Management
     **************************************************************************/
    /**
     * @brief Set the permissions of a role in a virtual space
     * @param name Name of the role
     * @param vsName Name of the virtual space
     * @param ops Operations to allow
     * @return true If the permissions were set successfully. False otherwise.
     * @note If the role does not exist, it will be created.
     */
    virtual bool setRolePermissions(const Role& name, const VSName& vsName, const std::vector<Operation>& ops) = 0;

    /**
     * @brief Remove the permissions of a role in a virtual space
     * @param name Name of the role
     * @param vsName Name of the virtual space
     * @param ops Operations to remove
     * @return true If the permissions were removed successfully. False otherwise.
     */
    virtual bool removeRolePermissions(const Role& name, const VSName& vsName, const std::vector<Operation>& ops) = 0;

    /**
     * @brief Get the permissions of a role in a virtual space
     * @param name Name of the role
     * @param vsName Name of the virtual space
     * @return std::unordered_set<Operation> Permissions of the role in the virtual space
     */
    virtual std::unordered_set<Operation> getRolePermissions(const Role& name, const VSName& vsName) const = 0;
};

/**
 * @brief The Virtual Space Authorization interface. This is used to authorize access to the
 * virtual space resources.
 *
 */
class IVirtualSpaceAuth
{

public:
    enum class Result
    {
        ALLOWED,
        DENIED,
        NOT_FOUND,
    };

    virtual ~IVirtualSpaceAuth() = default;

    /**
     * @brief Check if a role is allowed to perform an operation on a virtual space.
     *
     * @param role Role to check
     * @param op Operation to check
     * @param vsName Virtual Space Name to check against
     */
    virtual Result check(const Role& role, Operation op, const VSName& vsName) const = 0;

    /**
     * @brief Check if a role is allowed to perform an operation on a resource.
     *
     * The resource is searched in the all virtual spaces, and check the role against the
     * virtual space that contains the resource.
     * @param role Role to check
     * @param op Operation to check
     * @param vsName Virtual Space Name to check against
     * @param res Resource to check against
     */
    virtual Result check(const Role& role, Operation op, const Resource& res) const = 0;
};

} // namespace virtualspace

namespace std
{
template<>
struct hash<virtualspace::Resource>
{
    std::size_t operator()(const virtualspace::Resource& r) const
    {
        std::size_t h1 = std::hash<virtualspace::Component> {}(r.getComponent());
        std::size_t h2 = std::hash<std::string> {}(r.getString());
        return h1 ^ (h2 << 1); // Combina los hashes
    }
};
} // namespace std

#endif // _VIRTUALSPACE_IVIRTUALSPACE_HPP
