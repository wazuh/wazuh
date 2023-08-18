#include <store/store.hpp>

#include <list>
#include <set>

namespace
{

const std::string INTERNAL_NAMESPACE {"namespaces"};

// Cut names after a given size and delete duplicates
std::vector<base::Name>
cutName(const std::vector<base::Name>& names, const std::size_t size, const std::size_t depth = 1)
{

    std::set<base::Name> set {};
    const auto nSize = size + depth;

    for (const auto& name : names)
    {
        if (name.parts().size() >= nSize)
        {
            auto itBegin = name.parts().begin();
            auto itEnd = itBegin + nSize;

            std::vector<std::string> parts(itBegin, itEnd);

            set.insert(base::Name(parts));
        }
    }

    // Convert the set to a vector
    std::vector<base::Name> res {};
    res.reserve(set.size());
    for (const auto& name : set)
    {
        res.push_back(name);
    }

    return res;
}

}; // namespace
namespace store
{

/**
 * @brief Store::DBDocNames
 *
 * This class is used to store the document names and their associated NamespaceId.
 * It is used to cache the document names and their associated NamespaceId.
 * It is NOT thread safe.
 */
class Store::DBDocNames
{
private:
    std::unordered_map<base::Name, NamespaceId> m_nameToNS;       ///< Map from document name to NamespaceId
    std::unordered_multimap<NamespaceId, base::Name> m_nsToNames; ///< Map from NamespaceId to document names

public:
    DBDocNames() = default;

    /**
     * @brief Retrieve the NamespaceId associated with a given document.
     *
     * @param name Name of the document.
     * @return The NamespaceId if found; otherwise, std::nullopt.
     */
    std::optional<NamespaceId> getNamespaceId(const base::Name& name) const
    {
        auto it = m_nameToNS.find(name);
        if (it == m_nameToNS.end())
            return std::nullopt;

        return it->second;
    }

    /**
     * @brief Retrieve the all the document keys associated with a given NamespaceId.
     *
     * @param namespaceId NamespaceId to search for.
     * @return A vector with all the document names associated with the NamespaceId.
     */
    std::vector<base::Name> getDocumentKeys(const NamespaceId& namespaceId) const
    {
        auto range = m_nsToNames.equal_range(namespaceId);
        std::vector<base::Name> names;

        names.reserve(std::distance(range.first, range.second));
        for (auto it = range.first; it != range.second; ++it)
        {
            names.push_back(it->second);
        }
        return names;
    }

    /**
     * @brief Retrieve the all the document keys
     *
     */
    std::vector<base::Name> getDocumentKeys() const
    {
        std::vector<base::Name> names;
        names.reserve(m_nameToNS.size());

        for (const auto& [name, namespaceId] : m_nameToNS)
        {
            names.push_back(name);
        }
        return names;
    }

    bool existsName(const base::Name& name) const { return m_nameToNS.find(name) != m_nameToNS.end(); }

    bool existsPrefixName(const base::Name& prefix, bool subname = true) const
    {
        for (const auto& [key, value] : m_nameToNS)
        {
            // If is a subname, then the prefix must be smaller than the key
            if (subname && prefix.parts().size() >= key.parts().size())
            {
                continue;
            }
            // All elements of the prefix must be equal
            if (std::equal(prefix.parts().begin(), prefix.parts().end(), key.parts().begin()))
            {
                return true;
            }
        }

        return false;
    }

    std::vector<base::Name> filterByPrefix(const base::Name& prefix)
    {
        std::vector<base::Name> names;

        for (const auto& [key, value] : m_nameToNS)
        {
            // All elements of the prefix must be equal
            if (std::equal(prefix.parts().begin(), prefix.parts().end(), key.parts().begin()))
            {
                names.push_back(key);
            }
        }
        return names;
    }

    std::vector<base::Name> filterByPrefix(const base::Name& prefix, const NamespaceId& namespaceId)
    {
        std::vector<base::Name> names;

        for (const auto& [key, value] : m_nameToNS)
        {
            // All elements of the prefix must be equal
            if (value == namespaceId && std::equal(prefix.parts().begin(), prefix.parts().end(), key.parts().begin()))
            {
                names.push_back(key);
            }
        }
        return names;
    }

    /**
     * @brief Retrieve the all NamespaceIds.
     *
     * @return A vector with all the NamespaceIds.
     */
    std::vector<NamespaceId> getNamespaceIds() const
    {

        std::set<NamespaceId> set {};
        for (const auto& [namespaceId, name] : m_nsToNames)
        {
            set.insert(namespaceId);
        }

        std::vector<NamespaceId> namespaceIds;
        for (const auto& namespaceId : set)
        {
            namespaceIds.push_back(namespaceId);
        }

        return namespaceIds;
    }

    /**
     * @brief Change the NamespaceId associated with a given document key.
     *
     * @param name Name of the document.
     * @param namespaceId New NamespaceId to associate.
     * @return true if successfully changed; false otherwise.
     */
    bool changeNamespaceId(const base::Name& name, const NamespaceId& namespaceId)
    {
        auto itKeyToNS = m_nameToNS.find(name);
        if (itKeyToNS == m_nameToNS.end())
        {
            return false;
        }
        auto oldNamespaceId = itKeyToNS->second;
        itKeyToNS->second = namespaceId;

        // Remove previous association from m_nsToNames
        auto range = m_nsToNames.equal_range(oldNamespaceId);
        for (auto it = range.first; it != range.second; ++it)
        {
            if (it->second == name)
            {
                m_nsToNames.erase(it);
                break;
            }
        }

        // Add new association to m_nsToNames
        m_nsToNames.insert({namespaceId, name});

        return true;
    }

    /**
     * @brief Add a new document to the namespace with an associated NamespaceId.
     *
     * @param name Name of the document.
     * @param namespaceId NamespaceId to associate.
     * @return true if successfully added; false if document name already exists.
     */
    bool add(const base::Name& name, const NamespaceId& namespaceId)
    {
        if (m_nameToNS.find(name) != m_nameToNS.end())
        {
            return false;
        }
        m_nameToNS.insert({name, namespaceId});
        m_nsToNames.insert({namespaceId, name});

        return true;
    }

    /**
     * @brief Remove a document from the namespace.
     *
     * @param name Name of the document.
     * @return true if successfully removed; false otherwise.
     */
    bool del(const base::Name& name)
    {
        auto itKeyToNS = m_nameToNS.find(name);
        if (itKeyToNS == m_nameToNS.end())
        {
            return false;
        }
        auto namespaceId = itKeyToNS->second;
        m_nameToNS.erase(itKeyToNS);

        // Remove association from m_nsToNames
        auto range = m_nsToNames.equal_range(namespaceId);
        for (auto it = range.first; it != range.second; ++it)
        {
            if (it->second == name)
            {
                m_nsToNames.erase(it);
                break;
            }
        }
        return true;
    }

    bool existsNamespaceId(const NamespaceId& namespaceId) const
    {
        return m_nsToNames.find(namespaceId) != m_nsToNames.end();
    }
};

Store::Store(std::shared_ptr<IDriver> driver)
    : m_driver(std::move(driver))
    , m_cache(std::make_unique<DBDocNames>())
    , m_mutex()
    , m_prefixNS(INTERNAL_NAMESPACE)
{
    if (m_driver == nullptr)
    {
        throw std::runtime_error("Store driver cannot be null");
    }

    // Load the cache

    // TODO Remove 'this' of copy lambda (m_driver and m_store)
    auto visitor = [this](const base::Name& name, const NamespaceId& nsid, auto& visitorRef) -> void
    {
        // Is a document of nsid
        if (m_driver->existsDoc(name))
        {
            // Remove the namespace from the name
            const auto virtualNameR = realToVirtualName(name);
            const auto& virtualName = std::get_if<base::Name>(&virtualNameR);
            if (!virtualName)
            {
                throw std::runtime_error(fmt::format("Invalid document name '{}'", name.fullName()));
            }

            if (!m_cache->add(*virtualName, nsid))
            {
                LOG_WARNING("Document '{}' already exists in some namespace, "
                            "namespace is not consistent, will be fixed",
                            name.fullName());
                // TODO update namespace in cache
            }
            return;
        }

        const auto result = m_driver->readCol(name);
        if (const auto err = std::get_if<base::Error>(&result))
        {
            throw std::runtime_error(fmt::format("Error loading collection '{}': {}", name.fullName(), err->message));
        }

        const auto& list = std::get<Col>(result);
        for (const auto& subname : list)
        {
            visitorRef(subname, nsid, visitorRef);
        }
    };

    // No namespaces to load
    if (!m_driver->existsCol(m_prefixNS)) {
        return;
    }

    // Get all namespaces and load the cache
    const auto namespaces = m_driver->readCol(m_prefixNS);

    if (const auto err = std::get_if<base::Error>(&namespaces))
    {
        throw std::runtime_error(fmt::format("Error loading namespaces: {}", err->message));
    }

    const auto& list = std::get<Col>(namespaces);
    for (const auto& name : list)
    {
        if (name.parts().size() == m_prefixNS.parts().size() + NamespaceId::PARTS_NAMESPACE_SIZE
            && m_driver->existsCol(name))
        {
            visitor(name, NamespaceId(name.parts().back()), visitor);
            LOG_DEBUG("Loaded namespace '{}'", name.fullName());
        }
        else
        {
            throw std::runtime_error(fmt::format("Invalid namespace '{}', part size: {}, is collection: {}",
                                                 name.fullName(),
                                                 name.parts().size(),
                                                 m_driver->existsCol(name)));
        }
    }
}

Store::~Store() = default;

base::Name Store::virtualToRealName(const base::Name& virtualName, const NamespaceId& namespaceId) const
{
    return m_prefixNS + namespaceId.name() + virtualName;
}

base::RespOrError<base::Name> Store::realToVirtualName(const base::Name& realName) const
{
    // Remove de prefix
    const auto& partsRN = realName.parts();
    const auto prefixSize = m_prefixNS.parts().size() + NamespaceId::PARTS_NAMESPACE_SIZE;

    // The realname must have more parts than the prefix + namespace
    if (partsRN.size() < prefixSize)
    {
        return base::Error {"Invalid real name, too short"};
    }

    // Delete the namespace
    auto it = partsRN.begin();
    std::advance(it, prefixSize);

    return base::Name(std::vector<std::string>(it, partsRN.end()));
}

//----------------------------------------------------------------------------------------
//                                Read interface definition
//----------------------------------------------------------------------------------------

std::optional<NamespaceId> Store::getNamespace(const base::Name& name) const
{
    // If the document is a collection, then it does not have a NamespaceId
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    return m_cache->getNamespaceId(name);
}

base::RespOrError<Doc> Store::readDoc(const base::Name& name) const
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);

    // Check if the document exists
    const auto& namespaceId = m_cache->getNamespaceId(name);
    if (!namespaceId)
    {
        return base::Error {"Document does not exist"};
    }

    // Transform the virtual name to the real name
    const auto rname = virtualToRealName(name, *namespaceId);

    return m_driver->readDoc(rname);
}

std::vector<NamespaceId> Store::listNamespaces() const
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    return m_cache->getNamespaceIds();
}

base::RespOrError<Col> Store::readCol(const base::Name& name, const NamespaceId& namespaceId) const
{
    // Get all documents in the namespace
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    auto res = m_cache->filterByPrefix(name, namespaceId);

    if (res.empty())
    {
        return m_cache->existsNamespaceId(namespaceId) ? base::Error {"Namespace does not exist"}
                                                       : base::Error {"Collection does not exist in namespace"};
    }

    // Remove subnamespaces
    return cutName(res, name.parts().size());
}

base::RespOrError<Col> Store::readCol(const base::Name& name) const
{
    // Get all documents
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    auto res = m_cache->filterByPrefix(name);

    if (res.empty())
    {
        return base::Error {"Collection does not exist"};
    }

    // Remove subnamespaces
    return cutName(res, name.parts().size());
}

bool Store::exists(const base::Name& name) const
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    return m_cache->existsPrefixName(name, false);
}

bool Store::existsDoc(const base::Name& name) const
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    return m_cache->existsName(name);
}

bool Store::existsCol(const base::Name& name) const
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    return m_cache->existsPrefixName(name);
}

//----------------------------------------------------------------------------------------
//                                Write interface definition
//----------------------------------------------------------------------------------------

base::OptError Store::createDoc(const base::Name& name, const NamespaceId& namespaceId, const Doc& content)
{

    // Check if the document already exists
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    if (m_cache->existsName(name))
    {
        return base::Error {"Document already exists"};
    }

    auto rName = virtualToRealName(name, namespaceId);

    auto error = m_driver->createDoc(rName, content);
    if (error)
    {
        return error;
    }

    m_cache->add(name, namespaceId);
    return std::nullopt;
}

base::OptError Store::updateDoc(const base::Name& name, const Doc& content)
{
    // Shared lock because we only read the cache here
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    auto namespaceId = m_cache->getNamespaceId(name);
    if (!namespaceId)
    {
        return base::Error {"Document does not exist"};
    }

    // update the document
    auto rName = virtualToRealName(name, *namespaceId);
    return m_driver->updateDoc(rName, content);
}

base::OptError Store::upsertDoc(const base::Name& name, const NamespaceId& namespaceId, const Doc& content)
{

    std::unique_lock<std::shared_mutex> lock(m_mutex);
    auto namespaceIdCache = m_cache->getNamespaceId(name);

    if (namespaceIdCache && namespaceIdCache != namespaceId)
    {
        return base::Error {"Document already exists in another namespace"};
    }

    auto rName = virtualToRealName(name, namespaceId);
    auto error = m_driver->upsertDoc(rName, content);
    if (error)
    {
        return error;
    }

    if (!namespaceIdCache)
    {
        m_cache->add(name, namespaceId);
    }

    return std::nullopt;
}

base::OptError Store::deleteDoc(const base::Name& name)
{

    std::unique_lock<std::shared_mutex> lock(m_mutex);

    // Check if the document exists
    const auto& namespaceId = m_cache->getNamespaceId(name);
    if (!namespaceId)
    {
        return base::Error {"Document does not exist"};
    }

    auto rName = virtualToRealName(name, *namespaceId);

    auto error = m_driver->deleteDoc(rName);
    if (error)
    {
        return error;
    }

    m_cache->del(name);

    return std::nullopt;
}

base::OptError Store::deleteCol(const base::Name& name, const NamespaceId& namespaceId)
{

    std::unique_lock<std::shared_mutex> lock(m_mutex);

    // Check if the namespace exists
    if (!m_cache->existsNamespaceId(namespaceId))
    {
        return base::Error {"Namespace does not exist"};
    }

    // Check if the collection exists
    auto filteredDocs = m_cache->filterByPrefix(name, namespaceId);
    if (filteredDocs.empty())
    {
        return base::Error {"Collection does not exist"};
    }

    // Delete all documents in the collection
    // Acumuulate the errors
    std::vector<base::Error> errors;
    for (const auto& vName : filteredDocs)
    {
        auto rName = virtualToRealName(vName, namespaceId);
        auto error = m_driver->deleteDoc(rName);
        if (error)
        {
            errors.push_back(error.value());
        }
        else
        {
            m_cache->del(vName);
        }
    }

    // If there are errors, concatenate them
    if (!errors.empty())
    {
        std::string message;
        for (const auto& error : errors)
        {
            message += error.message + "\n";
        }
        return base::Error {message};
    }

    return std::nullopt;
}

base::OptError Store::deleteCol(const base::Name& name)
{

    std::unique_lock<std::shared_mutex> lock(m_mutex);

    // Check if the collection exists
    auto filteredDocs = m_cache->filterByPrefix(name);
    if (filteredDocs.empty())
    {
        return base::Error {"Collection does not exist"};
    }

    // Delete all documents in the collection
    // Acumuulate the errors
    std::vector<base::Error> errors;
    for (const auto& vName : filteredDocs)
    {
        auto namespaceId = m_cache->getNamespaceId(vName);
        auto rName = virtualToRealName(vName, namespaceId.value());
        auto error = m_driver->deleteDoc(rName);
        if (error)
        {
            errors.push_back(error.value());
        }
        else
        {
            m_cache->del(vName);
        }
    }

    // If there are errors, concatenate them
    if (!errors.empty())
    {
        std::string message;
        for (const auto& error : errors)
        {
            message += error.message + "\n";
        }
        return base::Error {message};
    }

    return std::nullopt;
}

base::OptError Store::createInternalDoc(const base::Name& name, const Doc& content)
{
    // The internal document not have a namespace, and not store in the cache

    // Check if the name have a same prefix as the internal namespace, and avoid it
    if (name.parts()[0] == m_prefixNS.parts()[0])
    {
        return base::Error {fmt::format("Invalid write internal document name '{}', cannot start with '{}'",
                                        name.fullName(),
                                        m_prefixNS.parts()[0])};
    }

    return m_driver->createDoc(name, content);
}

base::RespOrError<Doc> Store::readInternalDoc(const base::Name& name) const
{
    // No check if the document starts with the internal namespace, allow to read any document
    return m_driver->readDoc(name);
}

base::OptError Store::updateInternalDoc(const base::Name& name, const Doc& content)
{
    // Check if the name have a same prefix as the internal namespace, and avoid it
    if (name.parts()[0] == m_prefixNS.parts()[0])
    {
        return base::Error {fmt::format("Invalid update internal document name '{}', cannot start with '{}'",
                                        name.fullName(),
                                        m_prefixNS.parts()[0])};
    }
    return m_driver->updateDoc(name, content);
}

base::OptError Store::deleteInternalDoc(const base::Name& name)
{
    // Check if the name have a same prefix as the internal namespace, and avoid it
    if (name.parts()[0] == m_prefixNS.parts()[0])
    {
        return base::Error {fmt::format("Invalid delete internal document name '{}', cannot start with '{}'",
                                        name.fullName(),
                                        m_prefixNS.parts()[0])};
    }
    return m_driver->deleteDoc(name);
}

} // namespace store
