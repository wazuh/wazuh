#ifndef RNM_RESOURCE_NAMESPACE_MANAGER_HPP
#define RNM_RESOURCE_NAMESPACE_MANAGER_HPP

#include <shared_mutex>

#include <store/istore.hpp>

#include <rnm/iResourceNamespaceManager.hpp>

namespace rnm
{

using AuthFn = std::function<bool(const VSName&, const RoleName&, VSOperation)>;
// Store prefix for the resource namespace manager

class ResourceNamespaceManager : public IResourceNamespaceManager
{
private:
    std::weak_ptr<store::IStore> m_store;     ///< Store to use for catalog operations.
    AuthFn m_authFn;                          ///< Authorization function.

    const base::Name m_prefix;                      ///< Prefix for the resource namespace manager.
    class DBResourceNames;                    ///< PImpl for Cache for the resource names and virtual space names.
    std::unique_ptr<DBResourceNames> m_cache; ///< Cache for the resource names and virtual space names.
    mutable std::shared_mutex m_mutex;        ///< sync the m_cache with the store. and protect the m_cache access.

    /**
     * @brief Translate a resource name to a real space name.
     *
     * @param resourceName The name of the resource.
     * @param vsname The name of the virtual space.
     * @return base::Name The name of the resource in the store.
     */
    inline base::Name translateName(const base::Name& resourceName, const VSName& vsname) const;


    std::variant<json::Json, base::Error> getItem(const base::Name& item, const RoleName& role) const;

    std::variant<json::Json, base::Error> getCollection(const base::Name& collection, const RoleName& role) const;
public:
    /**
     * @brief Construct a new Resource Namespace Manager object using the store.
     */
    ResourceNamespaceManager(std::weak_ptr<store::IStore> store, AuthFn authFn, const std::string& prefix = "rnm");

    /*************************************************************************
     *                       ICatalogStoreReader
     *************************************************************************/
    /**
     * @copydoc ICatalogStoreReader::getVSName
     */
    std::optional<VSName> getVSName(const base::Name& resourceName) const override;

    /**
     * @copydoc ICatalogStoreReader::get
     */
    std::variant<json::Json, base::Error> get(const base::Name& item, const RoleName& role) const override;

    /*************************************************************************
     *                            ICatalogStore
     *************************************************************************/
    /**
     * @copydoc ICatalogStore::add
     */
    std::optional<base::Error>
    add(const base::Name& resourceName, const json::Json& content, const VSName& vsname, const RoleName& role) override;

    /**
     * @copydoc ICatalogStore::update
     */
    std::optional<base::Error>
    update(const base::Name& resourceName, const json::Json& content, const RoleName& role) override;

    /**
     * @copydoc ICatalogStore::del
     */
    std::optional<base::Error> del(const base::Name& resourceName, const RoleName& role) override;

    /**
     * @copydoc ICatalogStore::setVSName
     */
    std::optional<base::Error>
    setVSName(const base::Name& resourceName, const VSName& vsName, const RoleName& role) override;

    /*************************************************************************
     *                            KVDB
     *************************************************************************/
};

} // namespace rnm

#endif // RNM_RESOURCE_NAMESPACE_MANAGER_HPP
