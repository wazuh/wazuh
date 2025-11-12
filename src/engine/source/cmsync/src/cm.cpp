#include <cmsync/cmsync.hpp>

#include <base/logging.hpp>
#include <ctistore/adapter.hpp>

#include "coreoutput.hpp"

// Helper functions and definitions
namespace
{
const base::Name G_POLICY_NAME {"policy/wazuh/0"};     ///< Default policy name
const base::Name G_FILTER_NAME {"filter/allow-all/0"}; ///< Filter that allows all events

/**
 * @brief Get a shared pointer from a weak pointer or throw an exception if the pointer is expired
 * @tparam T Type of the pointer
 * @param weakPtr Weak pointer to get the shared pointer from
 * @param name Name of the instance to include in the exception message
 * @return const auto Shared pointer
 */
template<typename T>
auto getHandlerOrThrow(const std::weak_ptr<T>& weakPtr, std::string_view name)
{
    const auto ptr = weakPtr.lock();
    if (!ptr)
    {
        throw std::runtime_error(fmt::format("{} instance is no longer available", name));
    }
    return ptr;
}

/**
 * @brief Get a filter that allows all events
 * @return json::Json JSON representation of the filter
 */
json::Json getAllowAllFilter()
{
    // TODO: Move "/name" to common header
    json::Json filter {};
    filter.setString(G_FILTER_NAME.fullName(), "/name");
    return filter;
}

} // namespace

namespace cm::sync
{

/************************************************************************************
 * ICMSync interface implementation
 ************************************************************************************/
void CMSync::deploy(const std::shared_ptr<cti::store::ICMReader>& ctiStore)
{
    namespace acns = api::catalog;

    LOG_INFO("Starting Content Manager synchronization...");
    // Load from files and validate the core outputs
    wazuhCoreOutput(true);

    // TODO: We need validate the new ruleset before remove the old ones

    // Remove all decoders and integrations from the catalog.
    cleanCatalog(m_ctiNS, {acns::Resource::Type::decoder, acns::Resource::Type::integration});

    // Remove all outputs from the catalog.
    cleanCatalog(m_systemNS, {acns::Resource::Type::output});

    // Remove all policies
    cleanAllPolicies();

    // Remove all routes and environments from the orchestrator (policy instances).
    cleanAllRoutesAndEnvironments();

    // Delete all KVDB.
    cleanAllKVDB();

    {
        // Acquire shared read lock for the entire synchronization process
        // This prevents the Content Manager from updating the CTI Store while we're reading it
        auto readGuard = ctiStore->acquireReadGuard();

        // Load KVDB from Content Manager.
        pushKVDBsFromCM(ctiStore);

        // Load the outputs (May be use kvdb?) from local files.
        wazuhCoreOutput(false);

        // Load decoders and integrations from Content Manager.
        pushAssetsFromCM(ctiStore);

        // Load the allow-all filter if not exists.
        loadCoreFilter();

        // Create the security policy.
        pushPoliciesFromCM(ctiStore);
    }

    // Add core outputs to the policy
    pushOutputsToPolicy();

    // Create the route.
    loadDefaultRoute();

    LOG_INFO("Content Manager synchronization completed successfully.");
}

CMSync::CMSync(const std::shared_ptr<api::catalog::ICatalog>& catalog,
               const std::shared_ptr<kvdbManager::IKVDBManager>& kvdbManager,
               const std::shared_ptr<api::policy::IPolicy>& policyManager,
               const std::shared_ptr<router::IOrchestratorAPI>& orchestrator,
               const std::string& outputPath)

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
    m_coreOutputReader = std::make_unique<CoreOutputReader>(outputPath);
}

CMSync::~CMSync() = default;

/************************************************************************************
 * Other public methods or other interfaces can be added here
 ************************************************************************************/

// Clean catalog
void CMSync::cleanCatalog(const std::string& ns, const std::vector<api::catalog::Resource::Type>& typesToClean)
{
    namespace acns = api::catalog;

    const auto catalog = getHandlerOrThrow(m_catalog, "Catalog");

    // For each type, delete all resources of that type in the namespace
    for (const auto& type : typesToClean)
    {
        acns::Resource resource {acns::Resource::typeToStr(type), acns::Resource::Format::json};

        // Check if exists resources of this type in the namespace
        if (!catalog->collectionExists(resource, ns))
        {
            // No resources to delete
            continue;
        }

        // Delete all resources of this type in the namespace
        const auto error = catalog->deleteResource(resource, ns);
        if (error)
        {
            throw std::runtime_error(fmt::format("Failed to clean resources of type '{}' in namespace '{}': {}",
                                                 acns::Resource::typeToStr(type),
                                                 ns,
                                                 error->message));
        }
    }
}

// Clean KVDB TODO: Separe KVDB between CTI and User (Maybe ns?)
void CMSync::cleanAllKVDB()
{
    auto kvdbManager = getHandlerOrThrow(m_kvdbManager, "KVDB Manager");

    // List all DBs
    const auto dbs = kvdbManager->listDBs(false);

    // Check if KVDB are in use
    for (const auto& dbname : dbs)
    {
        const auto refCount = kvdbManager->getKVDBHandlersCount(dbname);
        if (refCount > 0)
        {
            throw std::runtime_error(
                fmt::format("Cannot delete KVDB '{}', it is in use by {} handlers", dbname, refCount));
        }
    }

    // Delete all DBs
    for (const auto& db : dbs)
    {
        auto error = kvdbManager->deleteDB(db);
        if (error)
        {
            // TODO: Log error and continue
            throw std::runtime_error(fmt::format("Failed to delete KVDB '{}': {}", db, error->message));
        }
    }
}

// Remove policies from catalog
void CMSync::cleanAllPolicies()
{
    const auto policyManager = getHandlerOrThrow(m_policyManager, "Policy Manager");

    // List all policies
    const auto respOrError = policyManager->list();
    if (base::isError(respOrError))
    {
        // TODO: Maybe no are policies and is not an error
        // We need differentiate between no policies and error, now we suppose that is no error
        return;
    }

    const auto& policies = base::getResponse(respOrError);

    // Delete all policies
    for (const auto& policy : policies)
    {
        // TODO: Check reason of error
        const auto error = policyManager->del(policy);
        if (error)
        {
            // TODO: Log error and continue
            std::string errorMsg = fmt::format("Failed to delete policy '{}': {}", policy.fullName(), error->message);
            throw std::runtime_error(errorMsg);
        }
    }
}

// Remove route and environment from the orchestrator
void CMSync::cleanAllRoutesAndEnvironments()
{
    const auto orchestrator = getHandlerOrThrow(m_orchestrator, "Orchestrator");

    // List all entries
    const auto entries = orchestrator->getEntries();

    // Delete all entries
    for (const auto& entry : entries)
    {
        const auto error = orchestrator->deleteEntry(entry.name());
        if (error)
        {
            // TODO: Log error and continue
            std::string errorMsg = fmt::format("Failed to delete entry '{}': {}", entry.name(), error->message);
            throw std::runtime_error(errorMsg);
        }
    }

    // Delete all test entries
    const auto testEntries = orchestrator->getTestEntries();
    for (const auto& testEntry : testEntries)
    {
        const auto error = orchestrator->deleteTestEntry(testEntry.name());
        if (error)
        {
            // TODO: Log error and continue
            std::string errorMsg =
                fmt::format("Failed to delete test entry '{}': {}", testEntry.name(), error->message);
            throw std::runtime_error(errorMsg);
        }
    }
}

void CMSync::pushKVDBsFromCM(const std::shared_ptr<cti::store::ICMReader>& ctiStore)
{

    // TODO: load all KVDB from CM Store, in the future we can filter by integration
    if (!ctiStore)
    {
        throw std::invalid_argument("CTI Store instance is null");
    }

    const auto kvdbManager = getHandlerOrThrow(m_kvdbManager, "KVDB Manager");
    // List all KVDB in the CM Store
    const auto kvdbList = ctiStore->listKVDB();

    for (const auto& kvdbName : kvdbList)
    {
        if (!ctiStore->kvdbExists(kvdbName))
        {
            throw std::runtime_error(fmt::format("KVDB '{}' does not exist in CM Store", kvdbName));
        }

        // Dump the KVDB content from the CM Store
        json::Json kvdbContent;
        try
        {
            json::Json rawCTIkvdbContent = ctiStore->kvdbDump(kvdbName);
            kvdbContent = cti::store::CTIAssetAdapter::adaptKVDB(rawCTIkvdbContent);

        }
        catch (const std::exception& e)
        {
            throw std::runtime_error(fmt::format("Failed to dump KVDB '{}' from CM Store,: {}", kvdbName, e.what()));
        }

        // Create the KVDB in the KVDB Manager from the dumped content
        const auto error = kvdbManager->createDB(kvdbName);
        if (error)
        {
            throw std::runtime_error(
                fmt::format("Failed to create KVDB '{}' in KVDB Manager: {}", kvdbName, error->message));
        }

        const auto loadError = kvdbManager->loadDBFromJson(kvdbName, kvdbContent);
        if (loadError)
        {
            throw std::runtime_error(
                fmt::format("Failed to load content into KVDB '{}' in KVDB Manager: {}", kvdbName, loadError->message));
        }
    }
}

void CMSync::pushAssetsFromCM(const std::shared_ptr<cti::store::ICMReader>& cmstore)
{
    if (!cmstore)
    {
        throw std::invalid_argument("CTI Store instance is null");
    }

    const auto catalog = getHandlerOrThrow(m_catalog, "Catalog");

    // Get all integration from CM store
    const auto integrationList = cmstore->getAssetList(cti::store::AssetType::INTEGRATION);

    // Lambda to get the list of decoders from a integration
    const auto getDecoderListFn = [&cmstore](const base::Name& integrationName) -> std::vector<base::Name>
    {
        // Get all decoders from a integration store
        std::vector<base::Name> decoderList;
        json::Json decoderDef {};
        decoderList.reserve(32); // Prevent multiple allocations
        try
        {
            const auto rawCTIdecoder = cmstore->getAsset(integrationName);
            const auto decoderDef = cti::store::CTIAssetAdapter::adaptAsset(rawCTIdecoder, "integration", cmstore);

            if (!decoderDef.isArray("/decoders"))
            {
                throw std::runtime_error(fmt::format(
                    "Invalid integration document for '{}', '/decoders' is not an array or does not exist",
                    integrationName.toStr()));
            }

            const auto arrayList = decoderDef.getArray("/decoders").value();
            for (const auto& jName : arrayList)
            {
                decoderList.push_back(jName.getString().value_or("Error, not and string decoder"));
            }
        }
        catch (const std::exception& e)
        {
            throw std::runtime_error(fmt::format("Failed to get decoder list from CM Store: {}", e.what()));
        }

        return decoderList;
    }; // TODO: Move to separate helper function

    // For each integration get his own decoders
    for (const auto& integrationName : integrationList)
    {
        if (!cmstore->assetExists(integrationName))
        {
            throw std::runtime_error(fmt::format("Integration asset '{}' does not exist in CM Store", integrationName));
        }

        // Get list of decoders from the integration
        const auto decoderList = getDecoderListFn(integrationName);

        // For each decoder get the asset and push to catalog
        for (const auto& decoderName : decoderList)
        {
            if (!cmstore->assetExists(decoderName))
            {
                throw std::runtime_error(fmt::format("Decoder asset '{}' does not exist in CM Store", decoderName));
            }
            const auto rawCTIdecoderAsset = cmstore->getAsset(decoderName);
            const auto decoderAsset = cti::store::CTIAssetAdapter::adaptAsset(rawCTIdecoderAsset, "decoder", cmstore);

            // Create decoder resource for CTI assets decoder collection
            api::catalog::Resource decoderResource {"decoder", api::catalog::Resource::Format::json};
            const auto error = catalog->postResource(decoderResource, m_ctiNS, decoderAsset.str());
            if (error)
            {
                throw std::runtime_error(
                    fmt::format("Failed to push decoder '{}' to catalog: {}", decoderName.toStr(), error->message));
            }
        }

        // Push integration asset to catalog
        try
        {
            api::catalog::Resource integrationResource {"integration", api::catalog::Resource::Format::json};
            const auto rawCTIintegrationAsset = cmstore->getAsset(integrationName);
            const auto integrationAsset =
                cti::store::CTIAssetAdapter::adaptAsset(rawCTIintegrationAsset, "integration", cmstore);
            const auto error = catalog->postResource(integrationResource, m_ctiNS, integrationAsset.str());
            if (error)
            {
                throw std::runtime_error(
                    fmt::format("Failed to push integration '{}' to catalog: {}", integrationName.toStr(), error->message));
            }
        }
        catch (const std::exception& e)
        {
            throw std::runtime_error(
                fmt::format("Failed to push integration '{}' to catalog: {}", integrationName.toStr(), e.what()));
        }
    }
}

void CMSync::pushPoliciesFromCM(const std::shared_ptr<cti::store::ICMReader>& cmstore)
{
    if (!cmstore)
    {
        throw std::invalid_argument("CTI Store instance is null");
    }

    const auto policyManager = getHandlerOrThrow(m_policyManager, "Policy Manager");

    // Create the default policy
    {
        const auto error = policyManager->create(G_POLICY_NAME);
        if (error)
        {
            throw std::runtime_error(
                fmt::format("Failed to create default policy '{}': {}", G_POLICY_NAME.fullName(), error->message));
        }
    }

    // Get all policy from CM store
    const auto integrationList = cmstore->getPolicyIntegrationList();

    // TODO Fix the order, should be pre-loaded
    const auto errorPrefix {"Clean the policy, it contains deleted assets: "};

    // For each policy get his own default parent and create the policy
    for (const auto& integration : integrationList)
    {
        base::Name policyIntegrationName{fmt::format("integration/{}/0", integration)};
        auto res = policyManager->addAsset(G_POLICY_NAME, store::NamespaceId(m_ctiNS), policyIntegrationName);

        if (base::isError(res) &&
            base::getError(res).message.find(errorPrefix) == std::string::npos) // Ignore if the asset is already in the policy
        {
            throw std::runtime_error(fmt::format("Failed to add asset '{}' to policy '{}': {}",
                                                 policyIntegrationName.fullName(),
                                                 G_POLICY_NAME.fullName(),
                                                 base::getError(res).message));
        }
    }
}

void CMSync::pushOutputsToPolicy()
{
    const auto policyManager = getHandlerOrThrow(m_policyManager, "Policy Manager");
    const auto catalog = getHandlerOrThrow(m_catalog, "Catalog");

    // Get all output from system namespace in the catalog
    const auto jlist =
        catalog->getResource(api::catalog::Resource {"output", api::catalog::Resource::Format::json}, m_systemNS);

    if (base::isError(jlist))
    {
        throw std::runtime_error(
            fmt::format("Failed to get output list from catalog: {}", base::getError(jlist).message));
    }

    const auto outputs = json::Json(base::getResponse(jlist).c_str());
    if (!outputs.isArray())
    {
        throw std::runtime_error("Invalid output list from catalog, not an array");
    }

    auto outputArray = outputs.getArray().value();
    std::vector<base::Name> outputNames;
    outputNames.reserve(outputArray.size()); // Prevent multiple allocations

    for (const auto& jName : outputArray)
    {
        // Get and validate the asset name
        const auto assetNameStr = jName.getString();
        if (!assetNameStr)
        {
            throw std::runtime_error("Invalid not string entry in output array from catalog");
        }

        try
        {
            outputNames.push_back(fmt::format("{}/0", assetNameStr.value()));
        }
        catch (const std::runtime_error& e)
        {
            throw std::runtime_error(fmt::format(
                "Invalid asset name '{}' in output array from catalog: {}", assetNameStr.value(), e.what()));
        }
    }

    // Add all outputs to the default policy
    for (const auto& outputName : outputNames)
    {
        auto res = policyManager->addAsset(G_POLICY_NAME, store::NamespaceId(m_systemNS), outputName);
        if (base::isError(res))
        {
            throw std::runtime_error(fmt::format("Failed to add output asset '{}' to policy '{}': {}",
                                                 outputName.fullName(),
                                                 G_POLICY_NAME.fullName(),
                                                 base::getError(res).message));
        }
    }
}

void CMSync::loadCoreFilter()
{
    const auto catalog = getHandlerOrThrow(m_catalog, "Catalog");

    // Check if filter already exists
    api::catalog::Resource filterResource {"filter", api::catalog::Resource::Format::json};
    if (catalog->existAsset(G_FILTER_NAME, m_systemNS))
    {
        // Filter already exists
        return;
    }

    // Create allow-all filter
    const auto filterContent = getAllowAllFilter().str();
    const auto error = catalog->postResource(filterResource, m_systemNS, filterContent);
    if (base::isError(error))
    {
        throw std::runtime_error(
            fmt::format("Failed to create filter '{}': {}", G_FILTER_NAME.fullName(), base::getError(error).message));
    }
}

// Add routes and environments to the orchestrator
void CMSync::loadDefaultRoute()
{
    const auto orchestrator = getHandlerOrThrow(m_orchestrator, "Orchestrator");

    // Create the default environment

    router::prod::EntryPost defaultEnv {
        "default",     // name
        G_POLICY_NAME, // policy
        G_FILTER_NAME, // filter
        255            // priority
    };
    const auto error = defaultEnv.validate();
    if (error)
    {
        throw std::runtime_error(fmt::format("Failed to validate default environment: {}", error->message));
    }

    const auto respOrError = orchestrator->postEntry(defaultEnv);
    if (base::isError(respOrError))
    {
        throw std::runtime_error(
            fmt::format("Failed to create default environment: {}", base::getError(respOrError).message));
    }
}

void CMSync::wazuhCoreOutput(bool onlyValidate) const
{
    namespace acns = api::catalog;
    const auto catalog = getHandlerOrThrow(m_catalog, "Catalog");

    // Filter ouput in outputPath
    std::vector<std::filesystem::path> ymlFiles = m_coreOutputReader->getAllOutputFiles();
    if (ymlFiles.empty())
    {
        throw std::runtime_error(
            fmt::format("No output configuration files found in '{}'", m_coreOutputReader->outputPathStr()));
    }

    // For each output file validate and push to catalog
    for (const auto& ymlFile : ymlFiles)
    {
        const auto [assetName, fileContent] = m_coreOutputReader->getOutputContent(ymlFile);
        api::catalog::Resource outputResource {onlyValidate ? assetName : "output", api::catalog::Resource::Format::yaml};
        const auto error = onlyValidate ? catalog->validateResource(outputResource, m_systemNS, fileContent)
                                        : catalog->postResource(outputResource, m_systemNS, fileContent);
        if (base::isError(error))
        {
            throw std::runtime_error(fmt::format("Failed to {} output '{}': {}",
                                                 onlyValidate ? "validate" : "push",
                                                 assetName.toStr(),
                                                 base::getError(error).message));
        }
    }
}

} // namespace cm::sync
