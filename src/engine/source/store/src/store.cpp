#include <store/store.hpp>

#include <algorithm>
#include <list>
#include <set>

#include <base/logging.hpp>

namespace
{

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

base::Name Store::sm_prefixNS {"namespaces"}; ///< Prefix for the namespaces.

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
        {
            return std::nullopt;
        }

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

    bool isPrefix(const base::Name& prefix, const base::Name& name, bool strict = true) const
    {
        if (strict)
        {
            // If the prefix is bigger or equal than the name, then it cannot be a prefix
            if (prefix.parts().size() >= name.parts().size())
            {
                return false;
            }
        }
        // If the prefix is bigger than the name, then it cannot be a prefix
        else if (prefix.parts().size() > name.parts().size())
        {
            return false;
        }

        // All elements of the prefix must be equal
        return std::equal(prefix.parts().cbegin(), prefix.parts().cend(), name.parts().cbegin());
    }

    bool existsPrefixName(const base::Name& prefix, bool strict = true) const
    {
        const auto found = std::find_if(m_nameToNS.cbegin(),
                                        m_nameToNS.cend(),
                                        [&](const auto& pair) { return isPrefix(prefix, pair.first, strict); });
        return found != m_nameToNS.cend();
    }

    std::vector<base::Name> filterByPrefix(const base::Name& prefix, const NamespaceId& namespaceId, bool strict = true)
    {
        std::vector<base::Name> names;
        for (const auto& [ns, name] : m_nsToNames)
        {
            if (ns == namespaceId && isPrefix(prefix, name, strict))
            {
                names.emplace_back(name);
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

        return std::vector<NamespaceId>(set.cbegin(), set.cend());
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
        if (m_nameToNS.find(name) != m_nameToNS.cend())
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
    void del(const base::Name& name)
    {
        auto itKeyToNS = m_nameToNS.find(name);
        if (itKeyToNS == m_nameToNS.end())
        {
            return;
        }

        auto range = m_nsToNames.equal_range(itKeyToNS->second);
        for (auto it = range.first; it != range.second; ++it)
        {
            if (it->second == name)
            {
                m_nameToNS.erase(itKeyToNS);
                m_nsToNames.erase(it);
                return;
            }
        }
    }

    void delCol(const base::Name& name, const NamespaceId& namespaceId)
    {
        // Fast filter by namespace
        auto range = m_nsToNames.equal_range(namespaceId);
        for (auto it = range.first; it != range.second;)
        {
            // Filter by prefix
            if (isPrefix(name, it->second))
            {
                m_nameToNS.erase(it->second); // Remove in name -> namespaceId
                it = m_nsToNames.erase(it);   // Remove in namespaceId -> name
            }
            else
            {
                ++it;
            }
        }
    }

    bool existsNamespaceId(const NamespaceId& namespaceId) const
    {
        return m_nsToNames.find(namespaceId) != m_nsToNames.cend();
    }
};

Store::Store(std::shared_ptr<IDriver> driver)
    : m_driver(std::move(driver))
    , m_cache(std::make_unique<DBDocNames>())
    , m_mutex()
{
    if (m_driver == nullptr)
    {
        throw std::runtime_error("Store driver cannot be null");
    }

    // Load the cache
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
                            "namespace is not consistent, will be ignored",
                            name.fullName());
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
    if (!m_driver->existsCol(sm_prefixNS))
    {
        return;
    }

    // Get all namespaces and load the cache
    const auto namespaces = m_driver->readCol(sm_prefixNS);

    if (const auto err = std::get_if<base::Error>(&namespaces))
    {
        throw std::runtime_error(fmt::format("Error loading namespaces: {}", err->message));
    }

    const auto& list = std::get<Col>(namespaces);
    for (const auto& name : list)
    {
        if (name.parts().size() == sm_prefixNS.parts().size() + NamespaceId::PARTS_NAMESPACE_SIZE
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
    // Retrieve real collection from cache
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    auto vcol = m_cache->filterByPrefix(name, namespaceId);
    if (vcol.empty())
    {
        return base::Error {fmt::format(
            "Collection '{}' does not exist on namespace '{}'", name.fullName(), namespaceId.name().fullName())};
    }

    return cutName(vcol, name.parts().size());
}

bool Store::existsDoc(const base::Name& name) const
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    return m_cache->existsName(name);
}

bool Store::existsCol(const base::Name& name, const NamespaceId& namespaceId) const
{
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    auto col = m_cache->filterByPrefix(name, namespaceId);
    return !col.empty();
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
    // Check if the namespace exists and the collection exists
    if (m_cache->filterByPrefix(name, namespaceId).empty())
    {
        return base::Error {"Collection does not exist"};
    }

    // Delete the collection
    auto error = m_driver->deleteCol(virtualToRealName(name, namespaceId));
    if (error)
    {
        return error;
    }

    // Update the cache
    m_cache->delCol(name, namespaceId);

    return std::nullopt;
}

base::OptError Store::createInternalDoc(const base::Name& name, const Doc& content)
{
    // The internal document not have a namespace, and not store in the cache

    // Check if the name have a same prefix as the internal namespace, and avoid it
    if (name.parts()[0] == sm_prefixNS.parts()[0])
    {
        return base::Error {fmt::format("Invalid write internal document name '{}', cannot start with '{}'",
                                        name.fullName(),
                                        sm_prefixNS.parts()[0])};
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
    if (name.parts()[0] == sm_prefixNS.parts()[0])
    {
        return base::Error {fmt::format("Invalid update internal document name '{}', cannot start with '{}'",
                                        name.fullName(),
                                        sm_prefixNS.parts()[0])};
    }
    return m_driver->updateDoc(name, content);
}

base::OptError Store::upsertInternalDoc(const base::Name& name, const Doc& content)
{
    // Check if the name have a same prefix as the internal namespace, and avoid it
    if (name.parts()[0] == sm_prefixNS.parts()[0])
    {
        return base::Error {fmt::format("Invalid update internal document name '{}', cannot start with '{}'",
                                        name.fullName(),
                                        sm_prefixNS.parts()[0])};
    }

    if (!m_driver->existsDoc(name))
    {
        return m_driver->createDoc(name, content);
    }

    return m_driver->updateDoc(name, content);
}

base::OptError Store::deleteInternalDoc(const base::Name& name)
{
    // Check if the name have a same prefix as the internal namespace, and avoid it
    if (name.parts()[0] == sm_prefixNS.parts()[0])
    {
        return base::Error {fmt::format("Invalid delete internal document name '{}', cannot start with '{}'",
                                        name.fullName(),
                                        sm_prefixNS.parts()[0])};
    }
    return m_driver->deleteDoc(name);
}

base::RespOrError<Col> Store::readInternalCol(const base::Name& name) const
{
    // No check if the document starts with the internal namespace, allow to read any document
    return m_driver->readCol(name);
}

bool Store::existsInternalDoc(const base::Name& name) const
{
    // No check if the document starts with the internal namespace, allow to read any document
    return m_driver->existsDoc(name);
}

} // namespace store
