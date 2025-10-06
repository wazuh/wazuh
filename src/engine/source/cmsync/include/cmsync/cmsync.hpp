/**
 * @file cmsync.hpp
 * @brief Content Manager Synchronization module between Content Manager and the catalog/kvdb/policy/orchestrator
 * subsystems
 *
 * This file contains the main implementation of the Content Manager Synchronization
 * system for the Wazuh Engine. The CMSync module is responsible for orchestrating
 * the deployment of security content (decoders, integrations, kvdbs, policies, etc.)
 * from Content Manager stores to the various engine subsystems.
 *
 * Key Components:
 * - CMSync: Main synchronization orchestrator class
 * - CoreOutputReader: Helper class for reading output configurations
 * - ICMSync: Interface definition for synchronization operations
 *
 */

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

/**
 * @brief Content Manager Synchronization implementation class
 *
 * The CMSync class is responsible for synchronizing and deploying content from the
 * Content Manager (CM) store to the Wazuh engine components. It orchestrates the
 * deployment process by coordinating multiple engine subsystems including:
 *
 * - Catalog management for storing decoders, integrations, and outputs
 * - KVDB (Key-Value Database) management for storing configuration data
 * - Policy management for security rules and policies
 * - Router orchestration for event routing and processing
 *
 * The deployment process follows a specific sequence:
 * 1. Validation of existing configurations
 * 2. Cleanup of old resources (decoders, integrations, policies, etc.)
 * 3. Loading new content from Content Manager store
 * 4. Setting up core filters and policies
 * 5. Configuring default routing rules
 *
 * @note TODO: The deployment process is atomic - if any step fails, the system should be left in a consistent state
 */
class CMSync : public ICMSync
{
public:
    CMSync() = delete;

    /**
     * @brief Initializes the CMSync object with references to all required engine components.
     *
     * @param catalog Shared pointer to the catalog management interface
     * @param kvdbManager Shared pointer to the KVDB management interface
     * @param policyManager Shared pointer to the policy management interface
     * @param orchestrator Shared pointer to the router orchestration interface
     * @param outputPath Path to the directory containing core output configuration files
     * @throws std::invalid_argument If any of the shared pointers are null
     * @throws std::runtime_error If the output path is invalid or inaccessible
     */
    explicit CMSync(const std::shared_ptr<api::catalog::ICatalog>& catalog,
                    const std::shared_ptr<kvdbManager::IKVDBManager>& kvdbManager,
                    const std::shared_ptr<api::policy::IPolicy>& policyManager,
                    const std::shared_ptr<router::IOrchestratorAPI>& orchestrator,
                    const std::string& outputPath);

    /**
     * @brief Default destructor
     */
    ~CMSync() override;

    /************************************************************************************
     * ICMSync interface implementation
     ************************************************************************************/

    /**
     * @brief Deploys content from the Content Manager store to engine components
     *
     * This is the main deployment method that orchestrates the complete synchronization
     * process. It performs the following operations in sequence:
     *
     * 1. Validates existing core output configurations
     * 2. Removes old content from catalog (decoders, integrations, outputs)
     * 3. Cleans up existing policies, routes, and KVDB entries
     * 4. Loads new KVDB data from Content Manager
     * 5. Deploys core outputs from local configuration files
     * 6. Loads decoders and integrations from Content Manager
     * 7. Creates core filtering rules
     * 8. Establishes security policies
     * 9. Configures default routing rules
     *
     * @param ctiStore Shared pointer to the Content Manager reader interface
     * @throws std::invalid_argument If ctiStore is null
     * @throws std::runtime_error If any deployment step fails
     */
    void deploy(const std::shared_ptr<cti::store::ICMReader>& ctiStore) override;

    /**
     * @brief Processes Wazuh core output configurations
     *
     * This method handles the loading and validation of core output configuration files.
     * It can operate in two modes: validation-only or full deployment.
     *
     * In validation mode, it only checks if the output files are properly formatted
     * and contain valid configurations. In deployment mode, it also loads the
     * configurations into the catalog for active use.
     *
     * @param onlyValidate If true, only validates configurations without loading them.
     *                     If false, validates and loads configurations into the catalog.
     * @throws std::runtime_error If validation fails or loading encounters errors
     */
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

    /**
     * @brief This method cleans up resources of specific types from the given namespace in the catalog.
     *
     * @param ns The namespace to clean resources from
     * @param typesToClean Vector of resource types to be removed from the namespace
     * @throws std::runtime_error If catalog operations fail
     */
    void cleanCatalog(const std::string& ns, const std::vector<api::catalog::Resource::Type>& typesToClean);

    /**
     * @brief Removes all KVDB instances from the system
     *
     * This method performs a complete cleanup of all Key-Value databases in the system.
     * It first checks if any databases are currently in use and then proceeds to
     * delete all existing databases.
     *
     * @warning This operation will delete all KVDB data - use with caution
     * @throws std::runtime_error If databases are in use or deletion fails
     * @todo Separate KVDB between CTI and User (Maybe use namespaces?)
     */
    void cleanAllKVDB();

    /**
     * @brief Removes all policies from the policy manager
     *
     * @throws std::runtime_error If policy listing or deletion fails
     */
    void cleanAllPolicies();

    /**
     * @brief Removes all routes and environments from the orchestrator
     *
     * @throws std::runtime_error If orchestrator operations fail
     */
    void cleanAllRoutesAndEnvironments();

    /**
     * @brief Loads KVDB data from the Content Manager store
     *
     * Retrieves all Key-Value databases from the Content Manager store and
     * creates them in the local KVDB manager with their content.
     *
     * @param ctiStore Shared pointer to the Content Manager reader interface
     * @throws std::invalid_argument If ctiStore is null
     * @throws std::runtime_error If KVDB creation or loading fails
     */
    void pushKVDBsFromCM(const std::shared_ptr<cti::store::ICMReader>& ctiStore);

    /**
     * @brief Loads decoders and integrations from the Content Manager store
     *
     * Retrieves all integration assets from the Content Manager and loads their
     * associated decoders into the catalog. Each integration contains multiple
     * decoders that are processed and stored in the CTI namespace.
     *
     * @param ctiStore Shared pointer to the Content Manager reader interface
     * @throws std::invalid_argument If ctiStore is null
     * @throws std::runtime_error If asset loading fails
     */
    void pushAssetsFromCM(const std::shared_ptr<cti::store::ICMReader>& ctiStore);

    /**
     * @brief Creates policies from Content Manager store data
     *
     * Creates the default policy and loads additional policies based on
     * integration configurations from the Content Manager store.
     *
     * @param ctiStore Shared pointer to the Content Manager reader interface
     * @throws std::invalid_argument If ctiStore is null
     * @throws std::runtime_error If policy creation fails
     */
    void pushPoliciesFromCM(const std::shared_ptr<cti::store::ICMReader>& ctiStore);

    /**
     * @brief Creates and loads the core allow-all filter (used on default route)
     *
     * @throws std::runtime_error If filter creation fails
     */
    void loadCoreFilter();

    /**
     * @brief Associates all available outputs in system namespace with the default policy
     *
     * Retrieves all output configurations from the system namespace and
     * adds them to the default policy for event processing.
     *
     * @throws std::runtime_error If output retrieval or policy association fails
     */
    void pushOutputsToPolicy();

    /**
     * @brief Sets up the default routing configuration
     *
     * Creates the default environment and routing entry in the orchestrator
     * using the default policy and allow-all filter.
     * @throws std::runtime_error If route creation or validation fails
     */
    void loadDefaultRoute();
};

} // namespace cm::sync

#endif // _CM_SYNC_CMSYNC
