#ifndef DNM_DOC_NAMESPACE_MANAGER_HPP
#define DNM_DOC_NAMESPACE_MANAGER_HPP

#include <shared_mutex>

#include <dnm/IDocumentManager.hpp>

#include "IDocStorage.hpp"

namespace dnm
{

class DocumentManager : public IDocumentManager
{
private:
    std::weak_ptr<IDocumentStorage> m_store; ///< Store to use for catalog operations.

    const base::Name m_prefix;               ///< Prefix for the doc namespace manager.
    class DBDocNames;                        ///< PImpl for Cache for the doc names and virtual space names.
    std::unique_ptr<DBDocNames> m_cache;     ///< Cache for the doc names and virtual space names.
    mutable std::shared_mutex m_mutex;       ///< sync the m_cache with the store. and protect the m_cache access.

    /**
     * @brief Translate a key name to a real name in the store.
     *
     * @param virtualName The name of the doc/collection in the virtual space.
     * @param namespaceID The namespace of the doc/collection in the virtual space.
     * @return base::Name The name of the doc/collection in the store.
     */
    inline base::Name virtualToRealName(const base::Name& virtualName, const NamespaceID& namespaceID) const;

    /**
     * @brief Translate a real name in the store to a virtual name.
     *
     * @param realName The name of the doc/collection in the store.
     * @return std::optional<base::Name> The name of the doc/collection in the namespace or std::nullopt if is not a
     * virtual name.
     */
    inline std::optional<base::Name> realToVirtualName(const base::Name& realName) const;

public:
    /**
     * @brief Construct a new Doc Namespace Manager object using the store.
     */
    DocumentManager(std::weak_ptr<IDocumentStorage> store, const std::string& prefix = "dnm");

    //----------------------------------------------------------------------------------------
    //                                Reader interface
    //----------------------------------------------------------------------------------------
    /**
     * @copydoc INamespacesReader::getNamespace
     */
    std::optional<NamespaceID> getNamespace(const base::Name& documentKey) const override;
    /**
     * @copydoc INamespacesReader::getDocument
     */
    std::variant<json::Json, base::Error> getDocument(const base::Name& key) const override;

    /**
     * @copydoc INamespacesReader::listNamespaces
     */
    std::vector<NamespaceID> listNamespaces() const override;

    /**
     * @copydoc INamespacesReader::listDocuments
     */
     std::optional<std::vector<base::Name>> listDocuments(const NamespaceID& namespaceID) const override;

    /**
     * @copydoc INamespacesReader::list
     */
    std::optional<std::vector<std::pair<base::Name, KeyType>>> list(const base::Name& key) const override;

    /**
     * @copydoc INamespacesReader::list
     */
    std::optional<std::vector<std::pair<base::Name, KeyType>>> list(const base::Name& key, const NamespaceID& namespaceID) const override;

    /**
     * @copydoc INamespacesReader::getType
     */
    std::optional<KeyType> getType(const base::Name& key) const override;

    //----------------------------------------------------------------------------------------
    //                                Write interface
    //----------------------------------------------------------------------------------------
    /**
     * @copydoc IDocumentManager::add
     */
    std::optional<base::Error>
    add(const base::Name& key, const json::Json& document, const NamespaceID& namespaceID) override;

    /**
     * @copydoc IDocumentManager::update
     */
    std::optional<base::Error> update(const base::Name& key, const json::Json& document) override;


    /**
    * @copydoc IDocumentManager::upsert
    */
    std::optional<base::Error> upsert(const base::Name& key, const json::Json& document, const NamespaceID& namespaceID) override;

    /**
     * @copydoc IDocumentManager::remove
     */
    std::optional<base::Error> remove(const base::Name& key) override;



};

} // namespace dnm

#endif // RNM_DOC_NAMESPACE_MANAGER_HPP
