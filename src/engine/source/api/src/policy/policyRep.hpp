#ifndef __API_POLICY_POLICYREP_HPP
#define __API_POLICY_POLICYREP_HPP

#include <map>
#include <set>
#include <sstream>

#include <fmt/format.h>
#include <store/istore.hpp>

namespace
{
constexpr auto NAME_PATH = "/name";
constexpr auto HASH_PATH = "/hash";
constexpr auto ASSETS_PATH = "/assets";
constexpr auto DEF_PARENTS_PATH = "/default_parents";
} // namespace

namespace api::policy
{

class Policy::PolicyRep
{
private:
    base::Name m_name;                                              ///< Policy name
    std::multimap<store::NamespaceId, base::Name> m_nss;            ///< Map of namespace and asset names
    std::multimap<store::NamespaceId, base::Name> m_defaultParents; ///< Map of namespace and default parent
    size_t m_hash;                                                  ///< Hash of the policy

    /**
     * @brief Get a string from the m_nss map, used to calculate the hash
     *
     * @return std::string
     */
    inline std::string nssToStr() const
    {
        std::string str;
        for (const auto& [ns, asset] : m_nss)
        {
            str += ns.name().fullName() + ":" + asset.fullName() + ";";
        }
        return str;
    }

public:
    PolicyRep(base::Name&& name,
              std::multimap<store::NamespaceId, base::Name>&& nss,
              size_t hash,
              std::multimap<store::NamespaceId, base::Name>&& defaultParents)
        : m_name {std::move(name)}
        , m_nss {std::move(nss)}
        , m_hash {hash}
        , m_defaultParents {std::move(defaultParents)}
    {
    }

    explicit PolicyRep(const base::Name& name)
        : m_name {name}
    {
        updateHash();
    }

    /**
     * @brief Update the hash of the policy
     *
     */
    inline void updateHash()
    {
        // Hash the policy nss and default parents
        std::hash<std::string> hasher;
        std::string str = nssToStr();
        for (auto it = m_defaultParents.begin(); it != m_defaultParents.end(); ++it)
        {
            str += it->first.name().fullName() + ":" + it->second.fullName() + ";";
        }
        m_hash = hasher(str);
    }

    /**
     * @brief Returns policy name
     *
     * @return base::Name
     */
    inline base::Name name() const { return m_name; }

    /**
     * @brief Returns policy version
     *
     * @return std::string
     */
    inline std::string version() const { return m_name.parts().back(); }

    /**
     * @brief Returns policy namespaces and assets
     *
     * @return std::multimap<store::NamespaceId, base::Name>
     */
    inline const std::multimap<store::NamespaceId, base::Name>& nss() const { return m_nss; }

    /**
     * @brief Returns policy hash
     *
     * @return size_t
     */
    inline size_t hash() const { return m_hash; }

    /**
     * @brief Set the Name of the policy
     *
     * @param name Policy name
     * @warning This method dont validate the name, should be validated before
     */
    inline void setName(const base::Name& name) { m_name = name; }

    /**
     * @brief Returns a list of namespaces in the policy
     *
     * @return std::list<store::NamespaceId>
     */
    inline std::list<store::NamespaceId> listNs() const
    {
        std::list<store::NamespaceId> nss;
        for (auto it = m_nss.cbegin(), end = m_nss.cend(); it != end; it = m_nss.upper_bound(it->first))
        {
            nss.emplace_back(it->first);
        }

        return nss;
    }

    /**
     * @brief List assets from a namespace
     *
     * @param namespaceId
     * @return std::list<base::Name>
     */
    inline std::list<base::Name> listAssets(const store::NamespaceId& namespaceId) const
    {
        std::list<base::Name> assets;
        auto range = m_nss.equal_range(namespaceId);
        for (auto it = range.first; it != range.second; ++it)
        {
            assets.emplace_back(it->second);
        }

        return assets;
    }

    /**
     * @brief Add a new asset to the policy
     *
     * @param namespaceId
     * @param assetName
     * @return base::OptError
     */
    inline base::OptError addAsset(const store::NamespaceId& namespaceId, const base::Name& assetName)
    {
        // Search if the asset already exists
        auto range = m_nss.equal_range(namespaceId);
        for (auto it = range.first; it != range.second; ++it)
        {
            if (it->second == assetName)
            {
                return base::Error {"Asset already exists"};
            }
        }

        // Add the asset
        m_nss.emplace(namespaceId, assetName);
        updateHash();
        return base::noError();
    }

    /**
     * @brief Remove an asset from the policy
     *
     * @param namespaceId
     * @param assetName
     * @return base::OptError
     */
    inline base::OptError delAsset(const store::NamespaceId& namespaceId, const base::Name& assetName)
    {
        // Search if the asset exists
        auto range = m_nss.equal_range(namespaceId);
        for (auto it = range.first; it != range.second; ++it)
        {
            if (it->second == assetName)
            {
                m_nss.erase(it);
                updateHash();
                return base::noError();
            }
        }

        return base::Error {"Asset not found"};
    }

    /**
     * @brief Build a PolicyRep from a policy document
     *
     * Store policy document structure (in store would be a JSON):
     * ---
     * name: <policy_name>
     * hash: <policy_hash>
     * assets: [<asset_name>, ...]
     * default_parents:
     *   <namespace_id>: <parent_name>
     *   ...
     * ---
     */
    static inline base::RespOrError<PolicyRep> fromDoc(const store::Doc& policyDoc,
                                                       std::shared_ptr<store::IStoreReader> store)
    {
        base::Name name {policyDoc.getString(NAME_PATH).value()};
        std::stringstream ss;
        ss << policyDoc.getString(HASH_PATH).value();
        size_t hash;
        ss >> hash;
        std::multimap<store::NamespaceId, base::Name> nss;
        std::multimap<store::NamespaceId, base::Name> defaultParents;

        // Assets
        auto assets = policyDoc.getArray(ASSETS_PATH);
        if (assets)
        {
            for (const auto& asset : assets.value())
            {
                auto assetName = base::Name {asset.getString().value()};
                auto ns = store->getNamespace(assetName);
                if (!ns)
                {
                    return base::Error {fmt::format("Asset not found: {}", assetName.fullName())};
                }

                nss.emplace(ns.value(), assetName);
            }
        }

        // Default parents
        auto defParents = policyDoc.getObject(DEF_PARENTS_PATH);
        if (defParents)
        {
            auto defParentsObj = std::move(defParents.value());
            for (const auto& [assetType, nsIdParent] : defParentsObj)
            {
                auto nsIdParentObj = nsIdParent.getObject();
                if (!nsIdParentObj)
                {
                    throw std::runtime_error("Default parent asset is not a object");
                }
                for (const auto& [ns, name] : nsIdParentObj.value())
                {
                    auto nsId = store::NamespaceId {ns};
                    auto parentName = base::Name {name.getString().value()};
                    defaultParents.emplace(nsId, parentName);
                }
            }
        }

        return PolicyRep {std::move(name), std::move(nss), hash, std::move(defaultParents)};
    }

    /**
     * @brief Build a policy document from a PolicyRep
     *
     * @return store::Doc
     */
    store::Doc toDoc() const
    {
        store::Doc policyDoc;
        policyDoc.setObject();

        // Name
        policyDoc.setString(m_name.fullName(), NAME_PATH);

        // Hash
        std::stringstream ss;
        ss << m_hash;
        policyDoc.setString(ss.str(), HASH_PATH);

        // Assets
        policyDoc.setArray(ASSETS_PATH);
        for (const auto& [nsId, asset] : m_nss)
        {
            policyDoc.appendString(asset.fullName(), ASSETS_PATH);
        }

        std::map<std::string, std::map<std::string, std::string>> assetTypeNamespaceParent;
        for (const auto& [namespaceId, parent] : m_defaultParents)
        {
            assetTypeNamespaceParent[parent.parts()[0]][namespaceId.str()] = parent;
        }

        // Default parents
        json::Json tmp;
        for (const auto& [namespaceId, parent] : assetTypeNamespaceParent["rule"])
        {
            auto key = "/rules" + json::Json::formatJsonPath(namespaceId);
            tmp.setString(parent, key);
        }

        for (const auto& [namespaceId, parent] : assetTypeNamespaceParent["decoder"])
        {
            auto key = "/decoders" + json::Json::formatJsonPath(namespaceId);
            tmp.setString(parent, key);
        }
        
        if (!tmp.isEmpty())
        {
            policyDoc.set(DEF_PARENTS_PATH, tmp);
        }
        else
        {
            policyDoc.setObject(DEF_PARENTS_PATH);
        }

        return policyDoc;
    }

    /**
     * @brief Print the policy in a human readable format
     *
     * TODO: Check and fix Format, json? yaml?
     * @param namespacesids Namespaces ids to filter. If empty, no filter is applied
     * @return std::string
     */
    std::string print(const std::vector<store::NamespaceId>& namespacesids) const
    {
        std::stringstream ss;
        // Name
        ss << "policy: " << m_name << std::endl;

        // Hash
        ss << "hash: " << m_hash << std::endl;

        // Assets
        {
            std::stringstream assetSS;
            bool hasAssets = false;
            for (const auto& [nsId, asset] : m_nss)
            {
                if (namespacesids.empty()
                    || std::find(namespacesids.begin(), namespacesids.end(), nsId) != namespacesids.end())
                {
                    hasAssets = true;
                    assetSS << "  - " << asset << std::endl;
                }
            }

            if (hasAssets)
            {
                ss << "assets:" << std::endl;
                ss << assetSS.str();
            }
        }

        // Default parents
        {
            std::stringstream defParentSS;
            bool hasDefParents = false;
            for (const auto& [nsId, parent] : m_defaultParents)
            {
                if (namespacesids.empty()
                    || std::find(namespacesids.begin(), namespacesids.end(), nsId) != namespacesids.end())
                {
                    hasDefParents = true;
                    defParentSS << "  - " << nsId.name() << ": " << parent << std::endl;
                }
            }

            if (hasDefParents)
            {
                ss << "default_parents:" << std::endl;
                ss << defParentSS.str();
            }
        }

        return ss.str();
    }

    base::RespOrError<std::list<base::Name>> getDefaultParent(const store::NamespaceId& namespaceId) const
    {
        auto range = m_defaultParents.equal_range(namespaceId);
        std::list<base::Name> parents;
        if (range.first == m_defaultParents.end())
        {
            return base::Error {"Namespace not found or no default parent"};
        }

        for (auto it = range.first; it != range.second; ++it)
        {
            parents.push_back(it->second);
        }
        
        return parents;
    }

    base::OptError setDefaultParent(const store::NamespaceId& namespaceId, const base::Name& parent)
    {
        auto range = m_defaultParents.equal_range(namespaceId);
        for (auto it = range.first; it != range.second; ++it)
        {
            if (it->second == parent)
            {
                return base::Error {"Namespace already has the provided default parent"};
            }
        }

        m_defaultParents.emplace(namespaceId, parent);
        updateHash();
        return base::noError();
    }

    base::OptError delDefaultParent(const store::NamespaceId& namespaceId)
    {
        auto range = m_defaultParents.equal_range(namespaceId);
        if (range.first == m_defaultParents.end())
        {
            return base::Error {"Namespace not found  or no default parent"};
        }

        m_defaultParents.erase(range.first, range.second);
        updateHash();
        return base::noError();
    }

    std::string getHash() const
    {
        std::stringstream ss;
        ss << m_hash;
        return ss.str();
    }
};

} // namespace api::policy

#endif // __API_POLICY_POLICYREP_HPP
