#include <rnm/resourceNamespaceManager.hpp>

#include <list>

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

constexpr std::size_t PARTS_NAMESPACE = 1;        ///< Number of parts in the namespace
constexpr std::size_t PARTS_VIRTUAL_RESOURCE = 3; ///< Number of parts in the virtual resource

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
    return name.parts().size() == PARTS_NAMESPACE;
}

inline bool isResourceCollection(const base::Name& resourceName)
{
    return resourceName.parts().size() < PARTS_VIRTUAL_RESOURCE;
}

inline bool isNameInCollection(const base::Name& name, const base::Name& collection)
{
    auto nameParts = name.parts();
    auto collectionParts = collection.parts();
    if (collectionParts.size() > nameParts.size())
    {
        return false;
    }
    for (size_t i = 0; i < collectionParts.size(); ++i)
    {
        if (collectionParts[i] != nameParts[i])
        {
            return false;
        }
    }
    return true;
}

/*************************************************************************
 *                        ResourceNamespaceManager
 ************************************************************************/
/**
 * @brief ResourceNamespaceManager::DBResourceNames
 *
 * This class is used to store the resource names and their associated VSName.
 * It is used to cache the resource names and their associated VSName.
 * It is NOT thread safe.
 */
class ResourceNamespaceManager::DBResourceNames
{
private:
    std::unordered_map<base::Name, VSName> nameToVS;       ///< Map from resource name to VSName
    std::unordered_multimap<VSName, base::Name> vsToNames; ///< Map from VSName to resource names

public:
    DBResourceNames() = default;

    /**
     * @brief Retrieve the VSName associated with a given resource name.
     *
     * @param resourceName Name of the resource.
     * @return The VSName if found; otherwise, std::nullopt.
     */
    std::optional<VSName> getVSName(const base::Name& resourceName) const
    {
        auto it = nameToVS.find(resourceName);
        if (it == nameToVS.end())
            return std::nullopt;

        return it->second;
    }

    /**
     * @brief Retrieve the all the resource names associated with a given VSName.
     *
     * @param vsname VSName to search for.
     * @return A vector with all the resource names associated with the VSName.
     */
    std::vector<base::Name> getResourceNames(const VSName& vsname) const
    {
        auto range = vsToNames.equal_range(vsname);
        std::vector<base::Name> resourceNames;

        resourceNames.reserve(std::distance(range.first, range.second));
        for (auto it = range.first; it != range.second; ++it)
        {
            resourceNames.push_back(it->second);
        }
        return resourceNames;
    }

    /**
     * @brief Retrieve the all VSNames.
     *
     * @return A vector with all the VSNames.
     */
    std::vector<VSName> getVSNames() const
    {
        std::vector<VSName> vsnames;
        for (const auto& [name, vsname] : nameToVS)
        {
            vsnames.push_back(vsname);
        }
        return vsnames;
    }

    /**
     * @brief Change the VSName associated with a given resource.
     *
     * @param resourceName Name of the resource.
     * @param vsname New VSName to associate.
     * @return true if successfully changed; false otherwise.
     */
    bool changeVSName(const base::Name& resourceName, const VSName& vsname)
    {
        auto itNameToVS = nameToVS.find(resourceName);
        if (itNameToVS == nameToVS.end())
        {
            return false;
        }
        auto oldVSName = itNameToVS->second;
        itNameToVS->second = vsname;

        // Remove previous association from vsToNames
        auto range = vsToNames.equal_range(oldVSName);
        for (auto it = range.first; it != range.second; ++it)
        {
            if (it->second == resourceName)
            {
                vsToNames.erase(it);
                break;
            }
        }

        // Add new association to vsToNames
        vsToNames.insert({vsname, resourceName});

        return true;
    }

    /**
     * @brief Add a new resource to the namespace with an associated VSName.
     *
     * @param resourceName Name of the resource.
     * @param vsname VSName to associate.
     * @return true if successfully added; false if resource name already exists.
     */
    bool add(const base::Name& resourceName, const VSName& vsname)
    {
        if (nameToVS.find(resourceName) != nameToVS.end())
        {
            return false;
        }
        nameToVS.insert({resourceName, vsname});
        vsToNames.insert({vsname, resourceName});

        return true;
    }

    /**
     * @brief Remove a resource from the namespace.
     *
     * @param resourceName Name of the resource.
     * @return true if successfully removed; false otherwise.
     */
    bool del(const base::Name& resourceName)
    {
        auto itNameToVS = nameToVS.find(resourceName);
        if (itNameToVS == nameToVS.end())
        {
            return false;
        }
        auto vsname = itNameToVS->second;
        nameToVS.erase(itNameToVS);

        // Remove association from vsToNames
        auto range = vsToNames.equal_range(vsname);
        for (auto it = range.first; it != range.second; ++it)
        {
            if (it->second == resourceName)
            {
                vsToNames.erase(it);
                break;
            }
        }
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

    // Load the cache
    auto storePtr = m_store.lock();
    if (!storePtr)
    {
        throw std::runtime_error("Store is not available");
    }

    // TODO: Contemplate the case where the store is empty
    // TODO: Analice add or change the store interface to return a vector of names whens get a collection
    std::list<base::Name> fullResouceName {};
    auto visitor = [&storePtr, &fullResouceName](const base::Name& name, int depth, auto& visitorRef) -> void
    {
        if (depth < 0){
            return;
        }
        depth--;


        auto resultStore = storePtr->get(name);
        if(const auto err = std::get_if<base::Error>(&resultStore))
        {
            throw std::runtime_error(fmt::format("Error loading namespaces: {}", err->message));
        }

        const auto& jChildNames = std::get<json::Json>(resultStore).getArray();
        if (!jChildNames)
        {
            throw std::runtime_error("Resource list is not an array");
        }

        for (const auto& jChildName : jChildNames.value())
        {
            const auto& jChildNameStr = jChildName.getString();
            if (!jChildNameStr)
            {
                throw std::runtime_error("Resource name is not a string");
            }
            if (depth == 0){
                fullResouceName.emplace_back(jChildNameStr.value());
            }
            else{
                visitorRef(jChildNameStr.value(), depth, visitorRef);
            }

        }

    };

    // Get the list of all resources in the store
    visitor(m_prefix, PARTS_VIRTUAL_RESOURCE, visitor);

    // Get

}

base::Name ResourceNamespaceManager::virtualToRealName(const base::Name& resourceName, const VSName& vsname) const
{
    return m_prefix + base::Name(vsname) + resourceName;
}

// Unused function
inline std::optional<std::pair<VSName, base::Name>> ResourceNamespaceManager::realToVirtualName(const base::Name& realName) const
{
    // Remove de prefix
    const auto& partsRN = realName.parts();
    const auto& partsPrefix = m_prefix.parts();
    VSName vsname;

    // The realname must have more parts than the prefix + namespace
    if (partsRN.size() + PARTS_NAMESPACE > partsRN.size() && std::equal(partsRN.begin(), partsRN.end(), partsRN.begin()))
    {
        auto it = partsRN.begin() + partsRN.size();
        if (it != partsRN.end())
        {
            vsname = *it;
            // Check if the VSName is valid
            if (!isVSNameValid(vsname))
            {
                return std::nullopt;
            }
            // Remove the VSName from the real name
            it++;
            base::Name resourceName(std::vector<std::string>(it, partsRN.end()));

            return std::make_pair(std::move(vsname), std::move(resourceName));
        }
    }

    return std::nullopt;
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
    // Step 1: Get all namespaces
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    auto vsnames = m_cache->getVSNames();

    // Step 2: Remove namespaces that the role does not have access to
    vsnames.erase(std::remove_if(vsnames.begin(),
                                 vsnames.end(),
                                 [&](const auto& vsname) { return !m_authFn(vsname, role, VSOperation::LIST); }),
                  vsnames.end());

    // Step 3: Get all name resources from the namespaces
    json::Json jCollection;
    jCollection.setArray();
    for (const auto& vsname : vsnames)
    {
        auto names = m_cache->getResourceNames(vsname);
        // Insert the names that are in the collection
        for (const auto& name : names)
        {
            if (isNameInCollection(name, collection))
            {
                jCollection.appendString(name.fullName());
            }
        }
    }

    return jCollection;
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

    auto name = virtualToRealName(item, *vsname);
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
    auto name = virtualToRealName(resourceName, vsname);
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

    auto name = virtualToRealName(resourceName, *vsname);
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
    auto name = virtualToRealName(resourceName, *vsname);

    return store->del(name);
}

std::optional<base::Error>
ResourceNamespaceManager::setVSName(const base::Name& resourceName, const VSName& vsname, const RoleName& role)
{
    // TODO implement
    return base::Error {"Not implemented"};
}

} // namespace rnm
