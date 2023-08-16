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
    std::shared_ptr<IDriver> m_driver;   ///< Store driver.

    class DBDocNames;                    ///< PImpl for Cache for the doc names and virtual space names.
    std::unique_ptr<DBDocNames> m_cache; ///< Cache for the doc names and virtual space names.
    mutable std::shared_mutex m_mutex;   ///< sync the m_cache with the store. and protect the m_cache access.

    /**
     * @brief Translate a key name to a real name in the store.
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

    base::OptError createDoc(const base::Name& name, const NamespaceId& namespaceId, const Doc& content) override;
    base::RespOrError<Doc> readDoc(const base::Name& name) const override;
    base::RespOrError<Col> readCol(const base::Name& name) const override;
    base::OptError updateDoc(const base::Name& name, const Doc& content) override;
    base::OptError upsertDoc(const base::Name& name, const NamespaceId& namespaceId, const Doc& content) override;
    base::OptError deleteDoc(const base::Name& name) override;
    base::OptError deleteCol(const base::Name& name) override;

    bool exists(const base::Name& name) const override;
    bool existsDoc(const base::Name& name) const override;
    bool existsCol(const base::Name& name) const override;

    base::OptError createNamespace(const NamespaceId& namespaceId) override;
    base::OptError deleteNamespace(const NamespaceId& namespaceId) override;

    std::vector<NamespaceId> listNamespaces() const override;
    base::OptError getNamespace(const base::Name& name) const override;
    base::RespOrError<Col> list(const NamespaceId& namespaceId) const override;
    base::RespOrError<Col> listDoc(const NamespaceId& namespaceId) const override;
    base::RespOrError<Col> listCol(const NamespaceId& namespaceId) const override;
};

} // namespace store
#endif // _STORE_HPP
