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
     *
     * @param policyDoc Policy document
     * @param store Store reader to get the namespace of the assets
     * @param ignoreMissing Return the policy even if it contains deleted assets, default is false
     *
     * @return base::RespOrError<PolicyRep> Policy representation or an error
     */
    static inline base::RespOrError<PolicyRep>
    fromDoc(const store::Doc& policyDoc, std::shared_ptr<store::IStoreReader> store, bool ignoreMissing = false)
    {
        base::Name name {policyDoc.getString(NAME_PATH).value()};
        std::stringstream ss;
        ss << policyDoc.getString(HASH_PATH).value();
        size_t hash;
        ss >> hash;
        std::multimap<store::NamespaceId, base::Name> nss;
        std::multimap<store::NamespaceId, base::Name> defaultParents;

        // Assets
        std::vector<std::string> missingAssetsNames;
        auto assets = policyDoc.getArray(ASSETS_PATH);
        if (assets)
        {
            for (const auto& asset : assets.value())
            {
                auto assetName = base::Name {asset.getString().value()};
                auto ns = store->getNamespace(assetName);
                if (!ns)
                {
                    missingAssetsNames.emplace_back(assetName.fullName());
                    continue;
                }

                nss.emplace(ns.value(), assetName);
            }
        }

        if (!ignoreMissing && !missingAssetsNames.empty())
        {
            return base::Error {
                fmt::format("Clean the policy, it contains deleted assets: {}", fmt::join(missingAssetsNames, ", "))};
        }

        // Default parents
        auto defParents = policyDoc.getObject(DEF_PARENTS_PATH);
        if (defParents)
        {
            auto defParentsObj = std::move(defParents.value());
            for (const auto& [ns, parents] : defParentsObj)
            {
                auto nsId = store::NamespaceId {ns};
                auto parentVect = parents.getArray();
                if (parentVect)
                {
                    for (auto i = 0; i < parentVect.value().size(); i++)
                    {
                        auto parentName = base::Name {parentVect.value()[i].getString().value_or("error_name")};
                        defaultParents.emplace(nsId, parentName);
                    }
                }
            }
        }

        return PolicyRep {std::move(name), std::move(nss), hash, std::move(defaultParents)};
    }

    /**
     * @brief Get the Deleted Assets from a policy document
     *
     * @param policyDoc Policy document
     * @param store Store reader to get the namespace of the assets
     * @return std::vector<std::string> list of deleted assets
     */
    static inline std::vector<std::string> getDeletedAssets(const store::Doc& policyDoc,
                                                            std::shared_ptr<store::IStoreReader> store)
    {
        base::Name name {policyDoc.getString(NAME_PATH).value()};

        // Assets
        std::vector<std::string> missingAssetsNames;
        auto assets = policyDoc.getArray(ASSETS_PATH);
        if (assets)
        {
            for (const auto& asset : assets.value())
            {
                auto assetName = base::Name {asset.getString().value()};
                auto ns = store->getNamespace(assetName);
                if (!ns)
                {
                    missingAssetsNames.emplace_back(assetName.fullName());
                }
            }
        }

        return missingAssetsNames;
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

        // Default parents
        std::map<std::string, std::vector<std::string>> nsParent;
        for (const auto& [ns, parent] : m_defaultParents)
        {
            auto it = nsParent.find(ns.str());
            if (it == nsParent.end())
            {
                nsParent[ns.str()] = {parent};
            }
            else
            {
                it->second.push_back(parent.toStr());
            }
        }

        json::Json defaultParentsObj;
        for (const auto& [ns, parents] : nsParent)
        {
            for (const auto& parent : parents)
            {
                defaultParentsObj.appendString(parent, json::Json::formatJsonPath(ns));
            }
        }

        if (!defaultParentsObj.isEmpty())
        {
            policyDoc.set(DEF_PARENTS_PATH, defaultParentsObj);
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
        if (range.first == range.second)
        {
            return base::Error {fmt::format("Namespace {} not found", namespaceId.str())};
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

    base::OptError delDefaultParent(const store::NamespaceId& namespaceId, const base::Name& parent)
    {
        auto range = m_defaultParents.equal_range(namespaceId);
        if (range.first == range.second)
        {
            return base::Error {fmt::format("Namespace {} not found", namespaceId.str())};
        }

        auto it = std::find_if(range.first, range.second, [&](const auto& pair) { return pair.second == parent; });
        if (it == range.second)
        {
            return base::Error {fmt::format("Parent {} not found in the specified namespace", parent.toStr())};
        }

        m_defaultParents.erase(it);
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
