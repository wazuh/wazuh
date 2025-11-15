#ifndef _CTI_STORE_CM
#define _CTI_STORE_CM

#include <memory>
#include <shared_mutex>

#include <ctistore/contentmanagerconfig.hpp>
#include <ctistore/ctistoragedb.hpp>
#include <ctistore/icmreader.hpp>

// ContentDownloader forward declaration - implementation in src/
namespace cti::store
{
class ContentDownloader;

/**
 * @brief Callback to notify when content is successfully downloaded and processed
 * Simple notification - no parameters needed, just signals that new content is available
 */
using ContentDeployCallback = std::function<void(const std::shared_ptr<cti::store::ICMReader>& ctiStore)>;

/**
 * @brief ContentManager class - Main CTI Store manager
 *
 * This class manages the CTI Store, providing access to downloaded assets
 * and handling content synchronization from the remote CTI platform.
 */
class ContentManager
    : public ICMReader
    , public std::enable_shared_from_this<ContentManager>
{
public:
    /**
     * @brief Constructor
     * @param config Configuration for the content downloader
     * @param deployCallback Optional callback to notify when content is successfully deployed
     */
    explicit ContentManager(const ContentManagerConfig& config = ContentManagerConfig {},
                            ContentDeployCallback deployCallback = nullptr);

    /**
     * @brief Destructor
     */
    ~ContentManager() override;

    /************************************************************************************
     * ICMReader interface implementation
     ************************************************************************************/

    /** @copydoc ICMReader::acquireReadGuard */
    ReadGuard acquireReadGuard() const override;

    /** @copydoc ICMReader::acquireWriteGuard */
    WriteGuard acquireWriteGuard() override;

    /** @copydoc ICMReader::getAssetList */
    std::vector<base::Name> getAssetList(cti::store::AssetType type) const override;

    /** @copydoc ICMReader::getAsset */
    json::Json getAsset(const base::Name& name) const override;

    /** @copydoc ICMReader::assetExists */
    bool assetExists(const base::Name& name) const override;

    /** @copydoc ICMReader::resolveNameFromUUID */
    std::string resolveNameFromUUID(const std::string& uuid) const override;

    /** @copydoc ICMReader::listKVDB */
    std::vector<std::string> listKVDB() const override;

    /** @copydoc ICMReader::listKVDB */
    std::vector<std::string> listKVDB(const base::Name& integrationName) const override;

    /** @copydoc ICMReader::kvdbExists */
    bool kvdbExists(const std::string& kdbName) const override;

    /** @copydoc ICMReader::kvdbDump */
    json::Json kvdbDump(const std::string& kdbName) const override;

    /** @copydoc ICMReader::getPolicyIntegrationList */
    std::vector<base::Name> getPolicyIntegrationList() const override;

    /** @copydoc ICMReader::getPolicy */
    json::Json getPolicy(const base::Name& name) const override;

    /** @copydoc ICMReader::getPolicyList */
    std::vector<base::Name> getPolicyList() const override;

    /** @copydoc ICMReader::policyExists */
    bool policyExists(const base::Name& name) const override;

    /************************************************************************************
     * Other public methods or other interfaces can be added here
     ************************************************************************************/

    /**
     * @brief Start content synchronization from remote CTI platform
     * @return true if started successfully
     */
    bool startSync();

    /**
     * @brief Stop content synchronization
     */
    void stopSync();

    /**
     * @brief Perform complete shutdown of ContentManager
     *
     * Stops content synchronization and closes the CTI storage database gracefully.
     * This method ensures that all pending operations are flushed to disk and all
     * resources are properly released.
     *
     * Should be called during engine shutdown to ensure clean database closure.
     * After calling this method, no further operations should be performed.
     */
    void shutdown();

    /**
     * @brief Check if synchronization is running
     * @return true if sync is active
     */
    bool isSyncRunning() const;

    /**
     * @brief Update synchronization interval
     * @param intervalSeconds New interval in seconds
     */
    void updateSyncInterval(size_t intervalSeconds);

    /**
     * @brief Get current configuration
     * @return Current configuration
     */
    const ContentManagerConfig& getConfig() const;

    /**
     * @brief Update configuration
     * @param config New configuration
     * @param restart If true, restarts sync with new config
     */
    void updateConfig(const ContentManagerConfig& config, bool restart = true);

private:
    // Internal unified processing function invoked by downloader callback
    FileProcessingResult processDownloadedContent(const std::string& message);

public: // Test support: delegate to downloader
    FileProcessingResult testProcessMessage(const std::string& message);

    /**
     * @brief Store policy data in local database
     * @param policyData Policy data to store
     * @return true if stored successfully
     */
    bool storePolicy(const json::Json& policyData);

    /**
     * @brief Store integration asset in local database
     * @param integration Integration JSON line
     * @return true if stored successfully
     */
    bool storeIntegration(const json::Json& integration);

    /**
     * @brief Store decoder asset in local database
     * @param decoder Decoder JSON line
     * @return true if stored successfully
     */
    bool storeDecoder(const json::Json& decoder);

    /**
     * @brief Store KVDB data in local database
     * @param kvdbData KVDB data to store
     * @return true if stored successfully
     */
    bool storeKVDB(const json::Json& kvdbData);

    /**
     * @brief Delete an asset by its resource ID
     * @param resourceId The UUID resource identifier
     * @return true if deleted successfully, false if not found
     */
    bool deleteAsset(const std::string& resourceId);

    /**
     * @brief Update an asset by its resource ID using JSON Patch operations
     * @param resourceId The UUID resource identifier
     * @param operations JSON array of patch operations
     * @return true if updated successfully, false if not found
     */
    bool updateAsset(const std::string& resourceId, const json::Json& operations);

private:
    std::unique_ptr<ContentDownloader> m_downloader;
    mutable std::shared_mutex m_mutex;
    ContentManagerConfig m_config;
    std::unique_ptr<CTIStorageDB> m_storage;
    ContentDeployCallback m_deployCallback;
};

} // namespace cti::store

#endif // _CTI_STORE_CM
