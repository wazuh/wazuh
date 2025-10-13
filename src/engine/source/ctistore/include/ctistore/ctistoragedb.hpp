#ifndef _CTI_STORE_STORAGE_DB_HPP
#define _CTI_STORE_STORAGE_DB_HPP

#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include <base/json.hpp>
#include <base/name.hpp>

namespace cti::store
{

/**
 * @brief Persistent storage for CTI assets and KVDBs backed by RocksDB.
 *
 * CTIStorageDB provides CRUD-like primitives to store and query:
 * - Policy documents
 * - Integration documents
 * - Decoder documents
 * - Key-Value databases (KVDB)
 *
 * It also maintains secondary indexes (by name/title) and relationship indexes
 * (e.g., integration -> related assets/KVDBs).
 *
 * Thread-safety: This class is thread-safe for single-writer, multiple-reader
 * scenarios. Write operations (storeXXX) must be called from a single thread,
 * while read operations (getXXX, existsXXX, listXXX) can be called concurrently
 * from multiple threads safely.
 */
class CTIStorageDB
{
public:
    /**
     * @brief Logical column families used inside RocksDB.
     */
    enum class ColumnFamily : std::uint8_t
    {
        METADATA,     ///< Internal metadata and bookkeeping.
        POLICY,       ///< Policy documents and policy-related indexes.
        INTEGRATION,  ///< Integration documents and name/id indexes.
        DECODER,      ///< Decoder documents and name/id indexes.
        KVDB          ///< KVDB catalog and relationship indexes.
    };

    /**
     * @brief Open (or create) a CTI storage at @p dbPath.
     *
     * @param dbPath Filesystem path to the RocksDB database.
     * @param useSharedBuffers If true, enable shared read cache and write buffer manager.
     * @throw std::runtime_error on failure to open or initialize column families.
     */
    explicit CTIStorageDB(const std::string& dbPath, bool useSharedBuffers = true);

    /// Destructor - must be defined in .cpp for PIMPL
    ~CTIStorageDB();

    CTIStorageDB(const CTIStorageDB&) = delete;
    CTIStorageDB& operator=(const CTIStorageDB&) = delete;

    /**
     * @brief Whether the underlying RocksDB handle is open.
     */
    bool isOpen() const;

    /**
     * @brief Perform a controlled shutdown of the database.
     *
     * Flushes all pending writes to disk and closes the database gracefully.
     * After calling this method, no further operations should be performed.
     * The destructor will automatically call this if not already called.
     *
     * @throw std::runtime_error on flush or close error.
     */
    void shutdown();

    /**
     * @brief Store (upsert) a policy document.
     *
     * Expects a valid JSON with required identifiers. Builds primary and
     * secondary (name) indexes and updates policy-related relationships.
     *
     * @param policyDoc Policy JSON document.
     * @throw std::runtime_error on validation or write error.
     */
    void storePolicy(const json::Json& policyDoc);

    /**
     * @brief Store (upsert) an integration document.
     *
     * Maintains id and name indexes and updates relationship indexes
     * (e.g., integration -> KVDBs / related assets).
     *
     * @param integrationDoc Integration JSON document.
     * @throw std::runtime_error on validation or write error.
     */
    void storeIntegration(const json::Json& integrationDoc);

    /**
     * @brief Store (upsert) a decoder document.
     *
     * @param decoderDoc Decoder JSON document.
     * @throw std::runtime_error on validation or write error.
     */
    void storeDecoder(const json::Json& decoderDoc);

    /**
     * @brief Register (upsert) a KVDB catalog entry and optional metadata.
     *
     * @param kvdbDoc KVDB descriptor JSON (name, owner integration, etc.).
     * @throw std::runtime_error on validation or write error.
     */
    void storeKVDB(const json::Json& kvdbDoc);

    /**
     * @brief Delete an asset by its UUID resource identifier.
     *
     * Searches across all asset column families (policy, integration, decoder, kvdb)
     * to find and delete the asset with the given resource ID. Also removes associated
     * name indexes and relationship metadata.
     *
     * @param resourceId The UUID resource identifier of the asset to delete.
     * @return true if the asset was found and deleted; false if not found.
     * @throw std::runtime_error on write error.
     */
    bool deleteAsset(const std::string& resourceId);

    /**
     * @brief Update an asset by its UUID resource identifier using JSON Patch operations.
     *
     * Searches across all asset column families (policy, integration, decoder, kvdb)
     * to find the asset with the given resource ID, applies the JSON Patch operations,
     * and stores the updated document back.
     *
     * @param resourceId The UUID resource identifier of the asset to update.
     * @param operations JSON array of JSON Patch operations (RFC 6902 format).
     *                   Each operation has: {"op": "replace|add|remove", "path": "/field/path", "value": ...}
     * @return true if the asset was found and updated; false if not found.
     * @throw std::runtime_error on validation, patch application error, or write error.
     */
    bool updateAsset(const std::string& resourceId, const json::Json& operations);

    /**
     * @brief List available assets by type.
     *
     * @param assetType One of: "policy", "integration", "decoder".
     * @return Vector of asset Names (titles) for the given type.
     * @throw std::runtime_error on invalid type or read error.
     */
    std::vector<base::Name> getAssetList(const std::string& assetType) const;

    /**
     * @brief Fetch an asset by id or name for a given type.
     *
     * @param name Asset identifier (can be an id or a title).
     * @param assetType One of: "policy", "integration", "decoder".
     * @return Parsed JSON asset document.
     * @throw std::runtime_error if not found or on read error.
     */
    json::Json getAsset(const base::Name& name, const std::string& assetType) const;

    /**
     * @brief Check asset existence by id or name for a given type.
     *
     * @param name Asset identifier (can be an id or a title).
     * @param assetType One of: "policy", "integration", "decoder".
     * @return true if it exists; false otherwise.
     * @throw std::runtime_error on invalid type or read error.
     */
    bool assetExists(const base::Name& name, const std::string& assetType) const;


    std::string resolveNameFromUUID(const std::string& uuid, const std::string& assetType) const;

    /**
     * @brief List all KVDB names.
     *
     * @return Vector with registered KVDB names.
     * @throw std::runtime_error on read error.
     */
    std::vector<std::string> getKVDBList() const;

    /**
     * @brief List KVDB names owned by a given integration.
     *
     * @param integrationName Integration name/title.
     * @return Vector of KVDB names (possibly empty).
     * @throw std::runtime_error on read error.
     */
    std::vector<std::string> getKVDBList(const base::Name& integrationName) const;

    /**
     * @brief Check if a KVDB exists.
     *
     * @param kvdbName KVDB name.
     * @return true if present; false otherwise.
     * @throw std::runtime_error on read error.
     */
    bool kvdbExists(const std::string& kvdbName) const;

    /**
     * @brief Dump KVDB content as JSON.
     *
     * The structure is implementation-defined (e.g., object of key->value).
     *
     * @param kvdbName KVDB name.
     * @return JSON dump of the KVDB.
     * @throw std::runtime_error if not found or on read error.
     */
    json::Json kvdbDump(const std::string& kvdbName) const;

    /**
     * @brief Get the list of integration names referenced by the policy.
     *
     * @return Vector of integration Names in the policy (order not guaranteed).
     * @throw std::runtime_error on read error.
     */
    std::vector<base::Name> getPolicyIntegrationList() const;

    /**
     * @brief Get a policy document by its ID or title.
     *
     * @param name Policy identifier (can be an ID or a title).
     * @return Parsed JSON policy document.
     * @throw std::runtime_error if not found or on read error.
     */
    json::Json getPolicy(const base::Name& name) const;

    /**
     * @brief List all available policy names (titles).
     *
     * @return Vector of policy Names (titles).
     * @throw std::runtime_error on read error.
     */
    std::vector<base::Name> getPolicyList() const;

    /**
     * @brief Check if a policy exists by ID or title.
     *
     * @param name Policy identifier (can be an ID or a title).
     * @return true if the policy exists; false otherwise.
     * @throw std::runtime_error on read error.
     */
    bool policyExists(const base::Name& name) const;

    /**
     * @brief Remove all data from all column families.
     *
     * Intended for testing or re-initialization scenarios.
     * @throw std::runtime_error on write error.
     */
    void clearAll();

    /**
     * @brief Return an approximate storage usage for a column family.
     *
     * Exact definition depends on RocksDB APIs (may be bytes on disk or
     * internal property-derived estimate).
     *
     * @param cf Column family.
     * @return Size/usage metric as a size_t.
     * @throw std::runtime_error on query error.
     */
    size_t getStorageStats(ColumnFamily cf) const;

    /**
     * @brief Lightweight schema/shape validation for documents.
     *
     * @param doc JSON document to validate.
     * @param expectedType One of: "policy", "integration", "decoder", "kvdb".
     * @return true if document shape matches expectations; false otherwise.
     */
    bool validateDocument(const json::Json& doc, const std::string& expectedType) const;

    // Static helper methods for asset type mappings
    static const std::unordered_map<std::string, ColumnFamily>& getAssetTypeToColumnFamily();
    static const std::unordered_map<std::string, std::string>& getAssetTypeToKeyPrefix();
    static const std::unordered_map<std::string, std::string>& getAssetTypeToNamePrefix();

private:
    // PIMPL idiom - hide RocksDB implementation details
    struct Impl;
    std::unique_ptr<Impl> m_pImpl;
};

} // namespace cti::store

#endif // _CTI_STORE_STORAGE_DB_HPP
