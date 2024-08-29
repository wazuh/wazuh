#ifndef _STORE_HPP
#define _STORE_HPP

#include <memory>
#include <shared_mutex>

#include <store/idriver.hpp>
#include <store/istore.hpp>

namespace store
{

class Store : public IStore
{
private:
    static base::Name sm_prefixNS; ///< Prefix for the namespaces.

    std::shared_ptr<IDriver> m_driver; ///< Store driver.

    class DBDocNames;                    ///< PImpl for Cache for the doc names and virtual space names.
    std::unique_ptr<DBDocNames> m_cache; ///< Cache for the doc names and virtual space names.
    mutable std::shared_mutex m_mutex;   ///< sync the m_cache with the store. and protect the m_cache access.

    /**
     * @brief Translate a virtual name to a real name in the store driver.
     *
     * @param virtualName The name of the doc/collection in the virtual space.
     * @param namespaceId The namespace of the doc/collection in the virtual space.
     * @return base::Name The name of the doc/collection in the store.
     */
    static inline base::Name virtualToRealName(const base::Name& virtualName, const NamespaceId& namespaceId)
    {
        return sm_prefixNS + namespaceId.name() + virtualName;
    }

    /**
     * @brief Translate a real name in the store to a virtual name.
     *
     * @param realName The name of the doc/collection in the store.
     * @return std::optional<base::Name> The name of the doc/collection in the namespace or std::nullopt if is not a
     * virtual name.
     */
    static inline base::RespOrError<base::Name> realToVirtualName(const base::Name& realName)
    {
        const auto& partsRN = realName.parts();

        // Real name has the form prefix + namespace + virtual name
        // Check size
        if (partsRN.size() < sm_prefixNS.parts().size() + NamespaceId::PARTS_NAMESPACE_SIZE + 1)
        {
            return base::Error {"Invalid real name, too short"};
        }

        // Check prefix
        for (auto i = 0; i < sm_prefixNS.parts().size(); ++i)
        {
            if (partsRN[i] != sm_prefixNS.parts()[i])
            {
                return base::Error {"Invalid real name, prefix does not match"};
            }
        }

        // Check namespaceId
        auto namespaceName = base::Name(
            std::vector<std::string>(partsRN.begin() + sm_prefixNS.parts().size(),
                                     partsRN.begin() + sm_prefixNS.parts().size() + NamespaceId::PARTS_NAMESPACE_SIZE));
        auto resp = NamespaceId::fromName(namespaceName);
        if (base::isError(resp))
        {
            return base::Error {"Invalid real name, namespace does not match"};
        }

        // Return the virtual name
        return base::Name(std::vector<std::string>(
            partsRN.begin() + sm_prefixNS.parts().size() + NamespaceId::PARTS_NAMESPACE_SIZE, partsRN.end()));
    }

    /**
     * @brief Translate a virtual col to a real col in the store driver.
     *
     * @param virtualCol The collection of virtual names.
     * @param namespaceId The namespace of the collection in the virtual space.
     * @return Col The collection of real names.
     */
    static inline Col virtualToRealCol(const Col& virtualCol, const NamespaceId& namespaceId)
    {
        Col realCol;
        for (const auto& virtualName : virtualCol)
        {
            realCol.emplace_back(virtualToRealName(virtualName, namespaceId));
        }
        return realCol;
    }

    /**
     * @brief Translate a real col in the store to a virtual col.
     *
     * @param realCol The collection of real names.
     * @return Col The collection of virtual names.
     */
    static inline base::RespOrError<Col> realToVirtualCol(const Col& realCol)
    {
        Col virtualCol;
        for (const auto& realName : realCol)
        {
            auto resp = realToVirtualName(realName);
            if (base::isError(resp))
            {
                return base::Error {fmt::format("Invalid real name '{}' in collection", realName.fullName())};
            }
            virtualCol.emplace_back(base::getResponse<base::Name>(resp));
        }

        return virtualCol;
    }

public:
    /**
     * @brief Construct a new Doc Namespace Manager object using the store.
     */
    Store(std::shared_ptr<IDriver> driver);

    ~Store();

    /**
     * @copydoc IStore::readDoc
     */
    base::RespOrError<Doc> readDoc(const base::Name& name) const override;

    /**
     * @copydoc IStore::readCol
     */
    base::RespOrError<Col> readCol(const base::Name& name, const NamespaceId& namespaceId) const override;

    /**
     * @copydoc IStore::existsDoc
     */
    bool existsDoc(const base::Name& name) const override;

    /**
     * @copydoc IStore::existsCol
     */
    bool existsCol(const base::Name& name, const NamespaceId& namespaceId) const override;

    /**
     * @copydoc IStore::listNamespaces
     */
    std::vector<NamespaceId> listNamespaces() const override;

    /**
     * @copydoc IStore::getNamespace
     */
    std::optional<NamespaceId> getNamespace(const base::Name& name) const override;

    /**
     * @copydoc IStore::createDoc
     */
    base::OptError createDoc(const base::Name& name, const NamespaceId& namespaceId, const Doc& content) override;

    /**
     * @copydoc IStore::updateDoc
     */
    base::OptError updateDoc(const base::Name& name, const Doc& content) override;

    /**
     * @copydoc IStore::upsertDoc
     */
    base::OptError upsertDoc(const base::Name& name, const NamespaceId& namespaceId, const Doc& content) override;

    /**
     * @copydoc IStore::deleteDoc
     */
    base::OptError deleteDoc(const base::Name& name) override;

    /**
     * @copydoc IStore::
     */
    base::OptError deleteCol(const base::Name& name, const NamespaceId& namespaceId) override;

    /**
     * @copydoc IStoreInternal::createInternalDoc
     */
    base::OptError createInternalDoc(const base::Name& name, const Doc& content) override;

    /**
     * @copydoc IStoreInternal::readInternalDoc
     */
    base::RespOrError<Doc> readInternalDoc(const base::Name& name) const override;

    /**
     * @copydoc IStoreInternal::updateInternalDoc
     */
    base::OptError updateInternalDoc(const base::Name& name, const Doc& content) override;

    /**
     * @copydoc IStoreInternal::upsertInternalDoc
     */
    base::OptError upsertInternalDoc(const base::Name& name, const Doc& content) override;

    /**
     * @copydoc IStoreInternal::deleteInternalDoc
     */
    base::OptError deleteInternalDoc(const base::Name& name) override;

    /**
     * @copydoc IStoreInternal::readInternalCol
     */
    base::RespOrError<Col> readInternalCol(const base::Name& name) const override;

    /**
     * @copydoc IStoreInternal::existsInternalDoc
     */
    bool existsInternalDoc(const base::Name& name) const override;
};

} // namespace store
#endif // _STORE_HPP
