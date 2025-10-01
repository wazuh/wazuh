#include <cmsync/cmsync.hpp>

#include <base/logging.hpp>

#include "coreoutput.hpp"

// Helper functions and definitions
namespace
{
const base::Name G_POLICY_NAME {"policy/wazuh/0"};
const base::Name G_FILTER_NAME {"filter/allow-all/0"}; // Filter for route

json::Json getAllowAllFilter()
{
    json::Json filter {};
    // TODO: Move "/name" to common header
    filter.setString(G_FILTER_NAME.fullName(), "/name");
    return filter;
}

} // namespace

namespace cm::sync
{

/************************************************************************************
 * ICMSync interface implementation
 ************************************************************************************/
void CMSync::deploy()
{
    return;
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
/************************************************************************************
 * Other public methods or other interfaces can be added here
 ************************************************************************************/

// Clean catalog
void CMSync::cleanCatalog(const std::string& ns)
{
    // use alias for api::catalog namespace
    namespace acns = api::catalog;

    const auto catalog = m_catalog.lock();
    if (!catalog)
    {
        throw std::runtime_error("Catalog instance is no longer available");
    }

    // Create decoder resource for CTI assets decoder collection
    acns::Resource decoderResource {acns::Resource::typeToStr(acns::Resource::Type::decoder),
                                    acns::Resource::Format::json};

    // Check if exists decoders in the CTI namespace
    if (!catalog->collectionExists(decoderResource, ns))
    {
        // No decoders to delete
        return;
    }

    // Delete all decoders in the CTI namespace
    const auto error = catalog->deleteResource(decoderResource, ns);
    if (error)
    {
        throw std::runtime_error(fmt::format("Failed to clean decoders in namespace '{}': {}", ns, error->message));
    }
}

// Clean KVDB TODO: Separe KVDB between CTI and User (Maybe ns?)
void CMSync::cleanAllKVDB()
{
    auto kvdbManager = m_kvdbManager.lock();
    if (!kvdbManager)
    {
        throw std::runtime_error("KVDB Manager instance is no longer available");
    }

    // List all DBs
    const auto dbs = kvdbManager->listDBs(false);

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

// Remove policys from catalog
void CMSync::cleanAllPolicys()
{
    const auto policyManager = m_policyManager.lock();
    if (!policyManager)
    {
        throw std::runtime_error("Policy Manager instance is no longer available");
    }

    // List all policys
    const auto respOrError = policyManager->list();
    if (base::isError(respOrError))
    {
        // TODO: Maybe no are policys
        throw std::runtime_error(fmt::format("Failed to list policys: {}", base::getError(respOrError).message));
    }

    const auto& policys = base::getResponse(respOrError);

    // Delete all policys
    for (const auto& policy : policys)
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
    const auto orchestrator = m_orchestrator.lock();
    if (!orchestrator)
    {
        throw std::runtime_error("Orchestrator instance is no longer available");
    }

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

void CMSync::pushAssetsFromCM(const std::shared_ptr<cti::store::ICMReader>& cmstore)
{
    if (!cmstore)
    {
        throw std::invalid_argument("CTI Store instance is null");
    }

    const auto catalog = m_catalog.lock();
    if (!catalog)
    {
        throw std::runtime_error("Catalog instance is no longer available");
    }

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
            const auto decodersPath =
                "/decoders"; // builder::syntax::integration::DECODER_PATH TODO: Move to common header
            decoderDef = cmstore->getAsset(integrationName);

            if (!decoderDef.isObject())
            {
                throw std::runtime_error("Invalid integration asset, not a JSON object");
            }

            if (!decoderDef.isArray(decodersPath))
            {
                // No decoders
                throw std::runtime_error("No decoders found in integration asset");
            }

            const auto resp = decoderDef.getArray(decodersPath);
            if (!resp)
            {
                throw std::runtime_error("Invalid decoders array in integration asset");
            }

            const auto& arrayList = resp.value();
            for (const auto& jName : arrayList)
            {
                // Get and validate the asset name
                const auto assetNameStr = jName.getString();
                if (!assetNameStr)
                {
                    throw std::runtime_error(fmt::format(
                        "Invalid not string entry in '{}' array for integration '{}'", decodersPath, integrationName));
                }

                base::Name assetName;
                try
                {
                    assetName = base::Name(assetNameStr.value());
                }
                catch (const std::runtime_error& e)
                {
                    throw std::runtime_error(fmt::format("Invalid asset name '{}' in integration '{}': {}",
                                                         assetNameStr.value(),
                                                         integrationName,
                                                         e.what()));
                }

                // Assert the asset name is a decoder
                // if (!syntax::name::isDecoder(assetName)) TODO: Use syntax helper
                if (assetName.parts().size() < 3 || assetName.parts()[0] != "decoder")
                {
                    throw std::runtime_error(fmt::format("Asset '{}' in integration '{}' is not of type '{}'",
                                                         assetName.toStr(),
                                                         integrationName,
                                                         "decoder"));
                }

                decoderList.push_back(assetName);
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
            const auto decoderAsset = cmstore->getAsset(decoderName);

            // Create decoder resource for CTI assets decoder collection
            try
            {
                api::catalog::Resource decoderResource {decoderName, api::catalog::Resource::Format::json};
                const auto error = catalog->postResource(decoderResource, m_ctiNS, decoderAsset.str());
            }
            catch (const std::exception& e)
            {
                throw std::runtime_error(
                    fmt::format("Failed to push decoder '{}' to catalog: {}", decoderName.toStr(), e.what()));
            }
        }

        // Push integration asset to catalog
        try
        {
            api::catalog::Resource integrationResource {integrationName, api::catalog::Resource::Format::json};
            const auto integrationAsset = cmstore->getAsset(integrationName);
            const auto error = catalog->postResource(integrationResource, m_ctiNS, integrationAsset.str());
        }
        catch (const std::exception& e)
        {
            throw std::runtime_error(
                fmt::format("Failed to push integration '{}' to catalog: {}", integrationName.toStr(), e.what()));
        }
    }
}

void CMSync::pushPolicysFromCM(const std::shared_ptr<cti::store::ICMReader>& cmstore)
{
    if (!cmstore)
    {
        throw std::invalid_argument("CTI Store instance is null");
    }

    const auto policyManager = m_policyManager.lock();
    if (!policyManager)
    {
        throw std::runtime_error("Policy Manager instance is no longer available");
    }

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

    // For each policy get his own default parent and create the policy
    for (const auto& policyIntegrationName : integrationList)
    {
        auto res = policyManager->addAsset(G_POLICY_NAME, store::NamespaceId(m_ctiNS), policyIntegrationName);
        if (base::isError(res))
        {
            throw std::runtime_error(fmt::format("Failed to add asset '{}' to policy '{}': {}",
                                                 policyIntegrationName.fullName(),
                                                 G_POLICY_NAME.fullName(),
                                                 base::getError(res).message));
        }
    }
}

// Add routes and environments to the orchestrator
void CMSync::loadDefaultRoute()
{
    const auto orchestrator = m_orchestrator.lock();
    if (!orchestrator)
    {
        throw std::runtime_error("Orchestrator instance is no longer available");
    }

    // Create the default environment
    {
        router::prod::EntryPost defaultEnv {
            "default",     // name
            G_POLICY_NAME, // policy
            G_FILTER_NAME, // filter
            255            // priority
        };
        const auto error = defaultEnv.validate();
        if (error)
        {
            throw std::runtime_error(fmt::format("Default environment is not valid: {}", error->message));
        }

        const auto respOrError = orchestrator->postEntry(defaultEnv);
        if (base::isError(respOrError))
        {
            throw std::runtime_error(
                fmt::format("Failed to create default environment: {}", base::getError(respOrError).message));
        }
    }
}

void CMSync::wazuhCoreOutput(bool onlyValidate) const
{
    namespace acns = api::catalog;
    const auto catalog = m_catalog.lock();
    if (!catalog)
    {
        throw std::runtime_error("Catalog instance is no longer available");
    }

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
        api::catalog::Resource outputResource {assetName, api::catalog::Resource::Format::yaml};
        const auto error = onlyValidate ? catalog->validateResource(outputResource, m_systemNS, fileContent)
                                        : catalog->postResource(outputResource, m_systemNS, fileContent);
        if (base::isError(error))
        {
            throw std::runtime_error(
                fmt::format("Failed to {} output '{}': {}", onlyValidate ? "validate" : "push", assetName.toStr(), base::getError(error).message));
        }
    }
}

} // namespace cm::sync
