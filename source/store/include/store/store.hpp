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
    base::Name m_prefixNS;               ///< Prefix for the namespaces.

    std::shared_ptr<IDriver> m_driver;   ///< Store driver.

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
    inline base::Name virtualToRealName(const base::Name& virtualName, const NamespaceId& namespaceId) const;

    /**
     * @brief Translate a real name in the store to a virtual name.
     *
     * @param realName The name of the doc/collection in the store.
     * @return std::optional<base::Name> The name of the doc/collection in the namespace or std::nullopt if is not a
     * virtual name.
     */
    inline base::RespOrError<base::Name> realToVirtualName(const base::Name& realName) const;

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
     * @copydoc IStore::readCol
     */
    base::RespOrError<Col> readCol(const base::Name& name) const override;

    /**
     * @copydoc IStore::exists
     */
    bool exists(const base::Name& name) const override;

     /**
     * @copydoc IStore::existsDoc
     */
    bool existsDoc(const base::Name& name) const override;

    /**
     * @copydoc IStore::existsCol
     */
    bool existsCol(const base::Name& name) const override;

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
     * @copydoc IStore::
     */
    base::OptError deleteCol(const base::Name& name) override;

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
     * @copydoc IStoreInternal::deleteInternalDoc
     */
    base::OptError deleteInternalDoc(const base::Name& name) override;
};

} // namespace store
#endif // _STORE_HPP
