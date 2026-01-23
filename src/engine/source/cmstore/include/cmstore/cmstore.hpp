#ifndef _CMSTORE_CMSTORE
#define _CMSTORE_CMSTORE

#include <filesystem>
#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>

#include <cmstore/icmstore.hpp>

namespace cm::store
{

/**
 * @brief Concrete implementation of ICMStore interface, representing the CMStore
 * @warning Only one instance of CMStore should exist to avoid race conditions on namespaces
 */
class CMStore : public ICMStore
{

    std::filesystem::path m_baseStoragePath;    ///< Base path for all namespaces
    std::filesystem::path m_defaultOutputsPath; ///< Default Outputs path for all namespaces
    std::unordered_map<NamespaceId, std::shared_ptr<ICMstoreNS>>
        m_namespaces;                  ///< Map of NamespaceId to CMStoreNS instances
    mutable std::shared_mutex m_mutex; ///< Mutex for namespaces map access

    /**
     * @brief Load all existing namespaces from disk into memory
     * @throw std::runtime_error if loading any namespace fails
     */
    void loadAllNamespacesFromDisk();

public:
    /**
     * @brief Create a CMStore instance at the given path
     * @param path the base path for all namespaces, should exist and be a directory
     * @param outputsPath the base path for all outputs, should exist and be a directory
     */
    CMStore(std::string_view path, std::string_view outputsPath);
    ~CMStore();

    /** @copydoc ICMStore::getNSReader */
    std::shared_ptr<ICMStoreNSReader> getNSReader(const NamespaceId& nsId) const override;

    /** @copydoc ICMStore::getNS */
    std::shared_ptr<ICMstoreNS> getNS(const NamespaceId& nsId) override;

    /** @copydoc ICMStore::createNamespace */
    std::shared_ptr<ICMstoreNS> createNamespace(const NamespaceId& nsId) override;

    /** @copydoc ICMStore::deleteNamespace */
    void deleteNamespace(const NamespaceId& nsId) override;

    /** @copydoc ICMStore::renameNamespace */
    void renameNamespace(const NamespaceId& from, const NamespaceId& to) override;

    /** @copydoc ICMStore::getNamespaces */
    std::vector<NamespaceId> getNamespaces() const override;

    /** @copydoc ICMStore::existsNamespace */
    bool existsNamespace(const NamespaceId& nsId) const override;
};

} // namespace cm::store

#endif // _CMSTORE_CMSTORE
