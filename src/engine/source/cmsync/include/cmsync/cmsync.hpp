#ifndef _CM_SYNC_CMSYNC
#define _CM_SYNC_CMSYNC

#include <memory>
#include <string>

#include <api/catalog/icatalog.hpp>
#include <api/policy/ipolicy.hpp>
#include <ctistore/icmreader.hpp>
#include <kvdb/ikvdbmanager.hpp>
#include <router/iapi.hpp>

#include <cmsync/icmsync.hpp>

namespace cm::sync
{

// Forward declarations
class CoreOutputReader;

// TODO: Documentation
class CMSync : public ICMSync
{
public:
    CMSync() = delete;
    explicit CMSync(const std::shared_ptr<api::catalog::ICatalog>& catalog,
                    const std::shared_ptr<kvdbManager::IKVDBManager>& kvdbManager,
                    const std::shared_ptr<api::policy::IPolicy>& policyManager,
                    const std::shared_ptr<router::IOrchestratorAPI>& orchestrator,
                    const std::string& outputPath);

    ~CMSync() override = default;

    /************************************************************************************
     * ICMSync interface implementation
     ************************************************************************************/
    /** @copydoc ICMSync::deploy */
    void deploy() override;

    /************************************************************************************
     * Other public methods or other interfaces can be added here
     ************************************************************************************/

     void wazuhCoreOutput(bool onlyValidate = false) const;

private:
    const std::string m_ctiNS = "cti";       ///< Namespace for CTI assets in the catalog
    const std::string m_systemNS = "system"; ///< Namespace for system assets in the catalog

    // Dependency instances
    std::weak_ptr<api::catalog::ICatalog> m_catalog {};        ///< Catalog handler
    std::weak_ptr<api::policy::IPolicy> m_policyManager {};    ///< Policy handler
    std::weak_ptr<kvdbManager::IKVDBManager> m_kvdbManager {}; ///< KVDB Manager handler
    std::weak_ptr<router::IOrchestratorAPI> m_orchestrator {}; ///< Orchestrator handler
    std::unique_ptr<CoreOutputReader> m_coreOutputReader {};   ///< Helper to raw read core output files

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
