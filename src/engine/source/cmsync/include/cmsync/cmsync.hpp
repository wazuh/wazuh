#ifndef _CM_SYNC_CMSYNC
#define _CM_SYNC_CMSYNC

#include <string>
#include <memory>

#include <api/catalog/icatalog.hpp>
#include <api/policy/ipolicy.hpp>
#include <kvdb/ikvdbmanager.hpp>
#include <router/iapi.hpp>
#include <ctistore/icmreader.hpp>

#include <cmsync/icmsync.hpp>


namespace cm::sync
{

// TODO: Documentation
class CMSync : public ICMSync
{
public:
    //CMSync() = delete;
    CMSync() = default; // TODO: Delete
    explicit CMSync(const std::shared_ptr<api::catalog::ICatalog>& catalog,
                    const std::shared_ptr<kvdbManager::IKVDBManager>& kvdbManager,
                    const std::shared_ptr<api::policy::IPolicy>& policyManager,
                    const std::shared_ptr<router::IOrchestratorAPI>& orchestrator,
                    const std::string& outputPath
                )

        : m_catalog(catalog)
        , m_kvdbManager(kvdbManager)
        , m_policyManager(policyManager)
        , m_orchestrator(orchestrator)
    {
        if (!catalog)
        {
            throw std::invalid_argument("Catalog instance is null");
        }
        if (!kvdbManager)
        {
            throw std::invalid_argument("KVDB Manager instance is null");
        }
        if (!policyManager)
        {
            throw std::invalid_argument("Policy Manager instance is null");
        }
        if (!orchestrator)
        {
            throw std::invalid_argument("Orchestrator instance is null");
        }

        // Check if output path exists and is a directory
        m_outputPath = std::filesystem::path(outputPath);
        if (!std::filesystem::exists(m_outputPath))
        {
            throw std::invalid_argument(fmt::format("Output configuration path '{}' does not exist", outputPath));
        }

        if (!std::filesystem::is_directory(m_outputPath))
        {
            throw std::invalid_argument(
                fmt::format("Output configuration path '{}' is not a directory", outputPath));
        }

        // Normalize path
        m_outputPath = std::filesystem::canonical(m_outputPath);
    }

    ~CMSync() override = default;

    /************************************************************************************
     * ICMSync interface implementation
     ************************************************************************************/
    /** @copydoc ICMSync::deploy */
    void deploy() override;


    /************************************************************************************
     * Other public methods or other interfaces can be added here
     ************************************************************************************/
    

private:

    const std::string m_ctiNS = "cti"; ///< Namespace for CTI assets in the catalog
    const std::string m_systemNS = "system"; ///< Namespace for system assets in the catalog
    const base::Name m_policyName {"policy/wazuh/0"};
    
    std::weak_ptr<api::catalog::ICatalog> m_catalog {}; ///< Weak pointer to the catalog instance
    std::weak_ptr<api::policy::IPolicy> m_policyManager {}; ///< Weak pointer to the policy manager instance
    std::weak_ptr<kvdbManager::IKVDBManager> m_kvdbManager {}; ///< Weak pointer to the KVDB manager instance
    std::weak_ptr<router::IOrchestratorAPI> m_orchestrator {}; ///< Weak pointer to the orchestrator instance
    std::filesystem::path m_outputPath {}; ///< Path of directory to load YML output files.


    // Clean catalog
    void cleanCatalog(const std::string& ns);

    // Clean KVDB TODO: Separe KVDB between CTI and User (Maybe ns?)
    void cleanAllKVDB();

    // Remove policys from catalog
    void cleanAllPolicys();

    // Remove route and environment from the orchestrator
    void cleanAllRoutesAndEnvironments();

    // Add KVDB from CM

    // Add the content of the catalog
    void pushAssetsFromCM(const std::shared_ptr<cti::store::ICMReader>& ctiStore);

    // Create the policy
    void pushPolicysFromCM(const std::shared_ptr<cti::store::ICMReader>& ctiStore);

    // Add routes and environments to the orchestrator
    void loadDefaultRoute();

    // Add wazuh-core integration to the catalog
    void pushWazuhCoreIntegration();

};

} // namespace cm::sync

#endif // _CM_SYNC_CMSYNC
