#include <rnm/resourceNamespaceManager.hpp>

/* lazy std::hash specialization for base::Name */
namespace std
{
template<>
struct hash<base::Name>
{
    size_t operator()(const base::Name& name) const
    {
        std::hash<std::string> hasher;
        size_t hashValue = 0;
        for (const auto& part : name.parts())
        {
            hashValue ^= hasher(part);
        }
        return hashValue;
    }
};
} // namespace std

namespace rnm
{

/*************************************************************************
                       Helper functions
 *************************************************************************/

// Names are valid if they are a single part.
inline bool isVSNameValid(const VSName& vsname)
{
    base::Name name;
    try
    {
        name = base::Name(vsname);
    }
    catch (const std::runtime_error& e)
    {
        return false;
    }
    return name.parts().size() == 1;
}

inline bool isRoleNameValid(const RoleName& roleName)
{
    return !roleName.empty();
}

inline bool isResourceCollection(const base::Name& resourceName)
{
    return resourceName.parts().size() < 2;
}

/*************************************************************************
 *                        ResourceNamespaceManager
 ************************************************************************/

// TODO: Implement thread safety for the DBResourceNames
class ResourceNamespaceManager::DBResourceNames
{
private:
    std::unordered_map<base::Name, VSName> nameToVS;

public:
    DBResourceNames()
        : nameToVS()
    {
    }

    /**
     * @brief Get the VSName for a resource.
     *
     * @param resourceName The name of the resource.
     * @return std::optional<VSName> The name of the virtual space or an empty optional if the resource does not exist.
     */
    std::optional<VSName> getVSName(const base::Name& resourceName) const
    {
        auto it = nameToVS.find(resourceName);
        if (it == nameToVS.end())
        {
            return std::nullopt;
        }
        return it->second;
    }

    /**
     * @brief Set the VSName for a resource.
     * @param resourceName The name of the resource.
     * @param vsname The name of the virtual space.
     * @return true if the operation was successful. False if the resource does not exist.
     */
    bool setVSName(const base::Name& resourceName, const VSName& vsname)
    {
        auto it = nameToVS.find(resourceName);
        if (it == nameToVS.end())
        {
            return false;
        }
        it->second = vsname;
        return true;
    }

    /**
     * @brief Add a resource to the namespace.
     *
     * @param resourceName The name of the resource.
     * @param vsname The name of the virtual space.
     * @return true if the operation was successful. False if the resource already exists.
     */
    bool add(const base::Name& resourceName, const VSName& vsname)
    {
        auto it = nameToVS.find(resourceName);
        if (it != nameToVS.end())
        {
            return false;
        }
        nameToVS.insert({resourceName, vsname});
        return true;
    }

    /**
     * @brief Delete a resource from the namespace.
     *
     * @param resourceName The name of the resource.
     * @return true if the operation was successful. False if the resource does not exist.
     */
    bool del(const base::Name& resourceName)
    {
        auto it = nameToVS.find(resourceName);
        if (it == nameToVS.end())
        {
            return false;
        }
        nameToVS.erase(it);
        return true;
    }
};

ResourceNamespaceManager::ResourceNamespaceManager(std::weak_ptr<store::IStore> store,
                                                   AuthFn authFn,
                                                   const std::string& prefix)
    : m_store(std::move(store))
    , m_authFn(std::move(authFn)) // Its necessary to move the authFn? use a std::bind and not a lambda?
    , m_cache(std::make_unique<DBResourceNames>())
    , m_mutex()
    , m_prefix(prefix)
{
    // TODO: Add check integrity
    // Implement the internal shared db resource against the store.
}

base::Name ResourceNamespaceManager::translateName(const base::Name& resourceName, const VSName& vsname) const
{
    return m_prefix + base::Name(vsname) + resourceName;
}

std::optional<VSName> ResourceNamespaceManager::getVSName(const base::Name& resourceName) const
{

    // If the resource is a collection, then it does not have a VSName
    if (!isResourceCollection(resourceName))
    {
        std::shared_lock<std::shared_mutex> lock(m_mutex);
        return m_cache->getVSName(resourceName);
    }

    return std::nullopt;
}

std::variant<json::Json, base::Error> ResourceNamespaceManager::getCollection(const base::Name& collection,

                                                                              const RoleName& role) const
{
    throw std::runtime_error("Not implemented");
}

std::variant<json::Json, base::Error> ResourceNamespaceManager::getItem(const base::Name& item,
                                                                        const RoleName& role) const
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    // Step 2: Check if the resource exists
    const auto& vsname = m_cache->getVSName(item);
    if (!vsname)
    {
        return base::Error {"Resource does not exist"};
    }

    // Step 3: Check if the role has access to the resource
    if (!m_authFn(*vsname, role, VSOperation::READ))
    {
        return base::Error {"Role does not have access to the resource"};
    }

    // Step 4: Get the resource from the store
    auto store = m_store.lock();
    if (!store)
    {
        return base::Error {"Store is not available"};
    }

    auto name = translateName(item, *vsname);
    auto resource = store->get(name);

    // Step 5: check if error
    if (std::holds_alternative<base::Error>(resource))
    {
        // TODO: Run check integrity / reload cache
        true;
    }
    return resource;
}

std::variant<json::Json, base::Error> ResourceNamespaceManager::get(const base::Name& item, const RoleName& role) const
{

    // Step 1: Check if iteam is a collection
    if (isResourceCollection(item))
    {
        return getCollection(item, role);
    }
    return getItem(item, role);
}

std::optional<base::Error> ResourceNamespaceManager::add(const base::Name& resourceName,
                                                         const json::Json& content,
                                                         const VSName& vsname,
                                                         const RoleName& role)
{
    // Step 1: Check if the resource is a collection
    if (isResourceCollection(resourceName))
    {
        return base::Error {"Cannot add a resource to a collection"};
    }

    // Step 2: Check if the resource already exists
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    if (m_cache->getVSName(resourceName))
    {
        return base::Error {"Resource already exists"};
    }

    // Step 3: Check if the role has access to the resource
    if (!m_authFn(vsname, role, VSOperation::WRITE))
    {
        return base::Error {"Role does not have access to the resource"};
    }

    // Step 4: Add the resource to the store
    auto store = m_store.lock();
    if (!store)
    {
        return base::Error {"Store is not available"};
    }
    auto name = translateName(resourceName, vsname);
    auto error = store->add(name, content);

    // Step 5: check if error
    if (error)
    {
        return error;
    }

    // Step 6: Add the resource to the namespace
    if (!m_cache->add(resourceName, vsname))
    {
        LOG_WARNING("Resource '{}' already exists in some namespace, "
                    "namespace is not consistent, will be fixed",
                    resourceName.fullName());
        // TODO update namespace in cache
    }

    return std::nullopt;
}

std::optional<base::Error>
ResourceNamespaceManager::update(const base::Name& resourceName, const json::Json& content, const RoleName& role)
{
    // Step 1: Check if the resource is a collection
    if (isResourceCollection(resourceName))
    {
        return base::Error {"Cannot update a collection"};
    }

    // Shared lock because we only read the cache here
    std::shared_lock<std::shared_mutex> lock(m_mutex);

    // Step 2: Check if the resource exists
    const auto& vsname = m_cache->getVSName(resourceName);
    if (!vsname)
    {
        return base::Error {"Resource does not exist"};
    }

    // Step 3: Check if the role has access to the resource
    if (!m_authFn(*vsname, role, VSOperation::WRITE))
    {
        return base::Error {"Role does not have access to the resource"};
    }

    // Step 4: Update the resource in the store
    auto store = m_store.lock();
    if (!store)
    {
        return base::Error {"Store is not available"};
    }

    auto name = translateName(resourceName, *vsname);
    return store->update(name, content);
}

std::optional<base::Error> ResourceNamespaceManager::del(const base::Name& resourceName, const RoleName& role)
{
    if (isResourceCollection(resourceName))
    {
        return base::Error {"Cannot delete a collection"};
    }

    std::unique_lock<std::shared_mutex> lock(m_mutex);
    // Step 2: Check if the resource exists
    const auto& vsname = m_cache->getVSName(resourceName);
    if (!vsname)
    {
        return base::Error {"Resource does not exist"};
    }

    // Step 3: Check if the role has access to the resource
    if (!m_authFn(*vsname, role, VSOperation::WRITE))
    {
        return base::Error {"Role does not have access to the resource"};
    }

    // Step 4: Delete the resource from the store
    auto store = m_store.lock();
    if (!store)
    {
        return base::Error {"Store is not available"};
    }

    m_cache->del(resourceName);
    auto name = translateName(resourceName, *vsname);

    return store->del(name);
}

std::optional<base::Error>
ResourceNamespaceManager::setVSName(const base::Name& resourceName, const VSName& vsname, const RoleName& role)
{
    // TODO implement
    return base::Error {"Not implemented"};
}

} // namespace rnm
