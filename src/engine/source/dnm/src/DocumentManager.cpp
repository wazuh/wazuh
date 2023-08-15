#include <dnm/DocumentManager.hpp>

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
constexpr std::size_t PARTS_VIRTUAL_DOCUMENT = 3; ///< Number of parts in the virtual document

namespace dnm
{

/*************************************************************************
                       Helper functions
 *************************************************************************/

// Names are valid if they are a single part.
inline bool isNamespaceIDValid(const NamespaceID& namespaceid)
{
    base::Name name;
    try
    {
        name = base::Name(namespaceid);
    }
    catch (const std::runtime_error& e)
    {
        return false;
    }
    return name.parts().size() == PARTS_NAMESPACE;
}

/*************************************************************************
 *                    Document Namespaces Manager
 ************************************************************************/
/**
 * @brief DocumentManager::DBDocNames
 *
 * This class is used to store the document names and their associated NamespaceID.
 * It is used to cache the document names and their associated NamespaceID.
 * It is NOT thread safe.
 */
class DocumentManager::DBDocNames
{
private:
    std::unordered_map<base::Name, NamespaceID> m_keyToNS;      ///< Map from document name to NamespaceID
    std::unordered_multimap<NamespaceID, base::Name> m_nsToKey; ///< Map from NamespaceID to document names

public:
    DBDocNames() = default;

    /**
     * @brief Retrieve the NamespaceID associated with a given document.
     *
     * @param documentKey Name of the document.
     * @return The NamespaceID if found; otherwise, std::nullopt.
     */
    std::optional<NamespaceID> getNamespaceID(const base::Name& documentKey) const
    {
        auto it = m_keyToNS.find(documentKey);
        if (it == m_keyToNS.end())
            return std::nullopt;

        return it->second;
    }

    /**
     * @brief Retrieve the all the document keys associated with a given NamespaceID.
     *
     * @param namespaceid NamespaceID to search for.
     * @return A vector with all the document names associated with the NamespaceID.
     */
    std::vector<base::Name> getDocumentKeys(const NamespaceID& namespaceid) const
    {
        auto range = m_nsToKey.equal_range(namespaceid);
        std::vector<base::Name> documentKeys;

        documentKeys.reserve(std::distance(range.first, range.second));
        for (auto it = range.first; it != range.second; ++it)
        {
            documentKeys.push_back(it->second);
        }
        return documentKeys;
    }

    /**
     * @brief Retrieve the all NamespaceIDs.
     *
     * @return A vector with all the NamespaceIDs.
     */
    std::vector<NamespaceID> getNamespaceIDs() const
    {
        std::vector<NamespaceID> namespaceids;
        namespaceids.reserve(m_keyToNS.size());

        for (const auto& [name, namespaceid] : m_keyToNS)
        {
            namespaceids.push_back(namespaceid);
        }
        return namespaceids;
    }

    /**
     * @brief Change the NamespaceID associated with a given document key.
     *
     * @param documentKey Name of the document.
     * @param namespaceid New NamespaceID to associate.
     * @return true if successfully changed; false otherwise.
     */
    bool changeNamespaceID(const base::Name& documentKey, const NamespaceID& namespaceid)
    {
        auto itKeyToNS = m_keyToNS.find(documentKey);
        if (itKeyToNS == m_keyToNS.end())
        {
            return false;
        }
        auto oldNamespaceID = itKeyToNS->second;
        itKeyToNS->second = namespaceid;

        // Remove previous association from m_nsToKey
        auto range = m_nsToKey.equal_range(oldNamespaceID);
        for (auto it = range.first; it != range.second; ++it)
        {
            if (it->second == documentKey)
            {
                m_nsToKey.erase(it);
                break;
            }
        }

        // Add new association to m_nsToKey
        m_nsToKey.insert({namespaceid, documentKey});

        return true;
    }

    /**
     * @brief Add a new document to the namespace with an associated NamespaceID.
     *
     * @param documentKey Name of the document.
     * @param namespaceid NamespaceID to associate.
     * @return true if successfully added; false if document name already exists.
     */
    bool add(const base::Name& documentKey, const NamespaceID& namespaceid)
    {
        if (m_keyToNS.find(documentKey) != m_keyToNS.end())
        {
            return false;
        }
        m_keyToNS.insert({documentKey, namespaceid});
        m_nsToKey.insert({namespaceid, documentKey});

        return true;
    }

    /**
     * @brief Remove a document from the namespace.
     *
     * @param documentKey Name of the document.
     * @return true if successfully removed; false otherwise.
     */
    bool del(const base::Name& documentKey)
    {
        auto itKeyToNS = m_keyToNS.find(documentKey);
        if (itKeyToNS == m_keyToNS.end())
        {
            return false;
        }
        auto namespaceid = itKeyToNS->second;
        m_keyToNS.erase(itKeyToNS);

        // Remove association from m_nsToKey
        auto range = m_nsToKey.equal_range(namespaceid);
        for (auto it = range.first; it != range.second; ++it)
        {
            if (it->second == documentKey)
            {
                m_nsToKey.erase(it);
                break;
            }
        }
        return true;
    }

    bool existsNamespaceID(const NamespaceID& namespaceid) const
    {
        return m_nsToKey.find(namespaceid) != m_nsToKey.end();
    }
};

DocumentManager::DocumentManager(std::weak_ptr<IDocumentStorage> store, const std::string& prefix)
    : m_store(std::move(store))
    , m_cache(std::make_unique<DBDocNames>())
    , m_mutex()
    , m_prefix(prefix)
{

    // Load the cache
    auto storePtr = m_store.lock();
    if (!storePtr)
    {
        throw std::runtime_error("Store is not available");
    }

    // TODO Remove 'this' of copy lambda
    auto visitor = [&storePtr, this](const base::Name& name, const NamespaceID& nsid, auto& visitorRef) -> void
    {
        const auto resultStore = storePtr->list(name);
        if (const auto err = std::get_if<base::Error>(&resultStore))
        {
            throw std::runtime_error(fmt::format("Error loading namespaces: {}", err->message));
        }

        const auto& list = std::get<std::list<std::pair<base::Name, KeyType>>>(resultStore);

        for (const auto& [name, keyType] : list)
        {
            switch (keyType)
            {
                case KeyType::DOCUMENT:
                {
                    if (!m_cache->add(name, nsid))
                    {
                        LOG_WARNING("Document '{}' already exists in some namespace, "
                                    "namespace is not consistent, will be fixed",
                                    name.fullName());
                        // TODO update namespace in cache
                    }
                    break;
                }
                case KeyType::COLLECTION: visitorRef(name, nsid, visitorRef); break;
                default: throw std::runtime_error("Invalid key type");
            }
        }
    };

    // Get all namespaces and load the cache
    const auto namespaces = storePtr->list(m_prefix);

    if (const auto err = std::get_if<base::Error>(&namespaces))
    {
        throw std::runtime_error(fmt::format("Error loading namespaces: {}", err->message));
    }

    const auto& list = std::get<std::list<std::pair<base::Name, KeyType>>>(namespaces);
    for (const auto& [name, keyType] : list)
    {
        if (keyType == KeyType::COLLECTION)
        {
            visitor(name, NamespaceID(name.parts().back()), visitor);
            LOG_DEBUG("Loaded namespace '{}'", name.fullName());
        }
        else
        {
            throw std::runtime_error("Inconsist collection");
        }
    }
}

base::Name DocumentManager::virtualToRealName(const base::Name& virtualName, const NamespaceID& namespaceid) const
{
    return m_prefix + base::Name(namespaceid) + virtualName;
}

std::optional<base::Name> DocumentManager::realToVirtualName(const base::Name& realKey) const
{
    // Remove de prefix
    const auto& partsRN = realKey.parts();
    const auto& partsPrefix = m_prefix.parts();

    // The realname must have more parts than the prefix + namespace
    if (partsPrefix.size() + PARTS_NAMESPACE < partsRN.size() && std::equal(partsPrefix.begin(), partsPrefix.end(), partsRN.begin()))
    {
        auto it = partsRN.begin() + partsPrefix.size();
        if (it != partsRN.end())
        {
            auto nsnameStr = *it;
            // Check if the VSName is valid
            if (!isNamespaceIDValid(nsnameStr))
            {
                return std::nullopt;
            }
            // Remove the VSName from the real name
            it++;
            return base::Name (std::vector<std::string>(it, partsRN.end()));
        }
    }

    return std::nullopt;
}

//----------------------------------------------------------------------------------------
//                                Read interface definition
//----------------------------------------------------------------------------------------

std::optional<NamespaceID> DocumentManager::getNamespace(const base::Name& documentKey) const
{
    // If the document is a collection, then it does not have a NamespaceID
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    return m_cache->getNamespaceID(documentKey);
}

std::variant<json::Json, base::Error> DocumentManager::getDocument(const base::Name& documentKey) const
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);

    // Check if the document exists
    const auto& namespaceid = m_cache->getNamespaceID(documentKey);
    if (!namespaceid)
    {
        return base::Error {"Document does not exist"};
    }

    // Get the document from the store
    auto store = m_store.lock();
    if (!store)
    {
        return base::Error {"Store is not available"};
    }

    // Transform the virtual name to the real name
    const auto name = virtualToRealName(documentKey, *namespaceid);

    return store->read(name);
}


 std::vector<NamespaceID> DocumentManager::listNamespaces() const {
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    return m_cache->getNamespaceIDs();
}

std::optional<std::vector<base::Name>> DocumentManager::listDocuments(const NamespaceID& namespaceid) const
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    auto res = m_cache->getDocumentKeys(namespaceid);
    return res.empty() ? std::nullopt : std::make_optional(std::move(res));
}


std::optional<std::vector<std::pair<base::Name, KeyType>>> DocumentManager::list(const base::Name& key, const NamespaceID& namespaceID) const
{
    // Get all namespaces
    std::shared_lock<std::shared_mutex> lock(m_mutex);

    // Check if the namespace exists
    if (!m_cache->existsNamespaceID(namespaceID))
    {
        return std::nullopt;
    }

    // Transform the virtual name to the real name
    const auto name = virtualToRealName(key, namespaceID);

    // List the keys
    auto store = m_store.lock();
    if (!store)
    {
        return std::nullopt;
    }

    auto result = store->list(name);
    if (const auto err = std::get_if<base::Error>(&result))
    {
        return std::nullopt;
    }

    // Delete the prefix from the keys
    const auto& list = std::get<std::list<std::pair<base::Name, KeyType>>>(result);
    auto res = std::vector<std::pair<base::Name, KeyType>>{};
    for (auto& [name, keyType] : list)
    {
        res.emplace_back(realToVirtualName(name).value(), keyType);
    }

    return res.size() == 0 ? std::nullopt : std::make_optional(std::move(res));
}

std::optional<std::vector<std::pair<base::Name, KeyType>>> DocumentManager::list(const base::Name& key) const
{
    // Get all namespaces
    auto namespaces = listNamespaces();

    // List all keys
    auto res = std::vector<std::pair<base::Name, KeyType>>{};

    for (const auto& namespaceid : namespaces)
    {
        auto listRes = list(key, namespaceid);
        if (listRes)
        {
            res.insert(res.end(), listRes->begin(), listRes->end());
        }
    }

    return res.size() == 0 ? std::nullopt : std::make_optional(std::move(res));
}

std::optional<KeyType> DocumentManager::getType(const base::Name& key) const {

    // Check if the key is document (if it has a namespace)
    auto namespaceid = getNamespace(key);
    if (namespaceid)
    {
        return KeyType::DOCUMENT;
    }

    // Check if the key is a collection
    auto listRes = list(key);
    if (listRes)
    {
        return KeyType::COLLECTION;
    }
}


//----------------------------------------------------------------------------------------
//                                Write interface definition
//----------------------------------------------------------------------------------------

std::optional<base::Error>
DocumentManager::add(const base::Name& key, const json::Json& document, const NamespaceID& namespaceID)
{

    // Check if the document already exists
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    if (m_cache->getNamespaceID(key))
    {
        return base::Error {"Document already exists"};
    }

    // Check if the namespace is valid
    if (!isNamespaceIDValid(namespaceID))
    {
        return base::Error {"Invalid namespace name"};
    }

    // Add the document to the store
    auto store = m_store.lock();
    if (!store)
    {
        return base::Error {"Store is not available"};
    }
    auto name = virtualToRealName(key, namespaceID);
    auto error = store->write(name, document);

    // Check if error
    if (error)
    {
        return error;
    }

    // Add the document to the cache
    if (!m_cache->add(key, namespaceID))
    {
        LOG_WARNING("Document '{}' already exists in some namespace, "
                    "namespace is not consistent, will be fixed",
                    key.fullName());
        return base::Error {"Document already exists"};
    }

    return std::nullopt;
}

std::optional<base::Error>
DocumentManager::update(const base::Name& key, const json::Json& document)
{
    // Shared lock because we only read the cache here
    std::shared_lock<std::shared_mutex> lock(m_mutex);

    // Check if the document exists
    const auto& namespaceid = m_cache->getNamespaceID(key);
    if (!namespaceid)
    {
        return base::Error {"Document does not exist"};
    }

    // Update the document in the store
    auto store = m_store.lock();
    if (!store)
    {
        return base::Error {"Store is not available"};
    }

    auto name = virtualToRealName(key, *namespaceid);
    return store->update(name, document);
}

std::optional<base::Error>
DocumentManager::upsert(const base::Name& key, const json::Json& document, const NamespaceID& namespaceID)
{

    // Check if the namespace is valid
    if (!isNamespaceIDValid(namespaceID))
    {
        return base::Error {"Invalid namespace name"};
    }

    // Get the store
    auto store = m_store.lock();
    if (!store)
    {
        return base::Error {"Store is not available"};
    }

    // Resolve the realName
    auto name = virtualToRealName(key, namespaceID);

    // Check if the document already exists
    std::unique_lock<std::shared_mutex> lock(m_mutex);

    // Update
    if (auto namespaceName = m_cache->getNamespaceID(key))
    {
        // Check if the namespace is the same
        if (*namespaceName != namespaceID)
        {
            return base::Error {"Document already exists in another namespace"};
        }

        // Update the document
        return store->update(name, document);
    }

    auto error = store->write(name, document);

    // Check if error
    if (error )
    {
        return error;
    }

    // Add the document to the cache
    if (!m_cache->add(key, namespaceID))
    {
        LOG_WARNING("Document '{}' already exists in some namespace, "
                    "namespace is not consistent, will be fixed",
                    key.fullName());
        return base::Error {"Document already exists"};
    }

    return std::nullopt;
}

std::optional<base::Error> DocumentManager::remove(const base::Name& key)
{

    std::unique_lock<std::shared_mutex> lock(m_mutex);

    // Check if the document exists
    const auto& namespaceid = m_cache->getNamespaceID(key);
    if (!namespaceid)
    {
        return base::Error {"Document does not exist"};
    }

    // Delete the document from the store
    auto store = m_store.lock();
    if (!store)
    {
        return base::Error {"Store is not available"};
    }

    auto name = virtualToRealName(key, *namespaceid);

    return store->remove(name);
}


} // namespace dnm
