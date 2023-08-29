#ifndef __API_POLICY_POLICYREP_HPP
#define __API_POLICY_POLICYREP_HPP

#include <map>

#include <fmt/format.h>
#include <store/istore.hpp>

namespace
{
// constexpr const char* NAME_PREFIX = "policy";
constexpr auto NAME_PATH = "/name";
constexpr auto HASH_PATH = "/hash";
constexpr auto NSS_PATH = "/namespaces";
constexpr auto NS_ASSETS_KEY = "assets";
constexpr auto NS_DEF_PARENT_KEY = "default_parent";
} // namespace

namespace api::policy
{

class Policy::PolicyRep
{
private:
    base::Name m_name;                                         ///< Policy name
    std::multimap<store::NamespaceId, base::Name> m_nss;       ///< Map of namespace and asset names
    std::map<store::NamespaceId, base::Name> m_defaultParents; ///< Map of namespace and default parent
    size_t m_hash;                                             ///< Hash of the policy

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
              std::map<store::NamespaceId, base::Name>&& defaultParents)
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
        m_hash = std::hash<std::string> {}(m_name.fullName()) ^ std::hash<std::string> {}(nssToStr());
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
     */
    static inline base::RespOrError<PolicyRep> fromDoc(const store::Doc& policyDoc)
    {
        base::Name name {policyDoc.getString(NAME_PATH).value()};
        // TODO add unsigned int64_t to json
        size_t hash {policyDoc.getInt64(HASH_PATH).value()};
        std::multimap<store::NamespaceId, base::Name> nss;
        std::map<store::NamespaceId, base::Name> defaultParents;

        auto optNss = policyDoc.getObject(NSS_PATH);
        if (optNss)
        {
            auto nssObj = std::move(optNss.value());
            // Iterate over namespaces
            for (const auto& [nsName, ns] : nssObj)
            {
                // Namespace id
                store::NamespaceId nsId {nsName};
                auto nsObj = ns.getObject().value();

                // Default parent
                auto defParentPos =
                    std::find_if(nsObj.begin(),
                                 nsObj.end(),
                                 [](const auto& tuple) { return std::get<0>(tuple) == NS_DEF_PARENT_KEY; });
                if (defParentPos != nsObj.end())
                {
                    defaultParents.emplace(nsId, base::Name {std::get<1>(*defParentPos).getString().value()});
                }

                // Iterate over assets
                auto assetsPos = std::find_if(
                    nsObj.begin(), nsObj.end(), [](const auto& tuple) { return std::get<0>(tuple) == NS_ASSETS_KEY; });
                if (assetsPos != nsObj.end())
                {
                    auto assets = std::get<1>(*assetsPos).getArray().value();
                    for (const auto& asset : assets)
                    {
                        nss.emplace(nsId, base::Name {asset.getString().value()});
                    }
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
        policyDoc.setInt64(m_hash, HASH_PATH);

        // Namespaces
        policyDoc.setObject(NSS_PATH);
        for (const auto& [nsId, asset] : m_nss)
        {
            auto nsPath = fmt::format("{}/{}", NSS_PATH, nsId.name().fullName());

            // Assets
            auto assetsPath = fmt::format("{}/{}", nsPath, NS_ASSETS_KEY);
            policyDoc.appendString(asset.fullName(), assetsPath);
        }

        // Default parents
        for (const auto& [nsId, parent] : m_defaultParents)
        {
            auto parentPath = fmt::format("{}/{}/{}", NSS_PATH, nsId.name().fullName(), NS_DEF_PARENT_KEY);

            policyDoc.setString(parent.fullName(), parentPath);
        }

        return policyDoc;
    }
};

} // namespace api::policy

#endif // __API_POLICY_POLICYREP_HPP