#include "builder.hpp"

#include <stdexcept>

#include <cmstore/categories.hpp>

#include "allowedFields.hpp"
#include "builders/ibuildCtx.hpp"
#include "policy/assetBuilder.hpp"
#include "policy/factory.hpp"
#include "policy/policy.hpp"
#include "register.hpp"
#include "registry.hpp"

namespace builder
{

class Builder::Registry final : public builders::RegistryType
{
};

Builder::Builder(const std::shared_ptr<cm::store::ICMStore>& cmStore,
                 const std::shared_ptr<schemf::IValidator>& schema,
                 const std::shared_ptr<defs::IDefinitionsBuilder>& definitionsBuilder,
                 const std::shared_ptr<IAllowedFields>& allowedFields,
                 const BuilderDeps& builderDeps)
    : m_cmStore {cmStore}
    , m_schema {schema}
    , m_definitionsBuilder {definitionsBuilder}
    , m_allowedFields {allowedFields}
{
    if (!m_cmStore)
    {
        throw std::runtime_error {"CMStore interface is null"};
    }

    if (!m_schema)
    {
        throw std::runtime_error {"Schema interface is null"};
    }

    if (!m_definitionsBuilder)
    {
        throw std::runtime_error {"Definitions builder is null"};
    }

    if (!m_allowedFields)
    {
        throw std::runtime_error {"Allowed fields is null"};
    }

    // Registry
    m_registry = std::static_pointer_cast<Registry>(Registry::create<builder::Registry>());

    detail::registerStageBuilders<Registry>(m_registry, builderDeps);
    detail::registerOpBuilders<Registry>(m_registry, builderDeps);
}

std::shared_ptr<IPolicy> Builder::buildPolicy(const cm::store::NamespaceId& namespaceId, bool trace, bool sandbox) const
{
    auto policy = std::make_shared<policy::Policy>(
        namespaceId, m_cmStore, m_definitionsBuilder, m_registry, m_schema, m_allowedFields, trace, sandbox);

    return policy;
}

base::Expression Builder::buildAsset(const base::Name& name, const cm::store::NamespaceId& namespaceId) const
{
    const auto nsReader = m_cmStore->getNSReader(namespaceId);
    const auto& jsonAsset = nsReader->getAssetByName(name);
    auto buildCtx = std::make_shared<builders::BuildCtx>();
    buildCtx->setRegistry(m_registry);
    buildCtx->setValidator(m_schema);
    buildCtx->setAllowedFields(m_allowedFields);
    buildCtx->runState().trace = false;
    buildCtx->runState().sandbox = false;

    auto assetBuilder = std::make_shared<policy::AssetBuilder>(buildCtx, m_definitionsBuilder);
    auto asset = (*assetBuilder)(jsonAsset);

    return asset.expression();
}

base::OptError Builder::softIntegrationValidate(const std::shared_ptr<cm::store::ICMStoreNSReader>& nsReader,
                                                const cm::store::dataType::Integration& integration) const
{
    if (!integration.isEnabled())
    {
        return base::noError();
    }

    const auto& namespaceId = nsReader->getNamespaceId();
    const auto& integrationName = integration.getName();

    // Decoders
    for (const auto& uuid : integration.getDecodersByUUID())
    {
        std::string decoderName;
        try
        {
            decoderName = std::get<0>(nsReader->resolveNameFromUUID(uuid));
        }
        catch (const std::exception& e)
        {
            return base::Error {fmt::format(
                "Failed to resolve name for decoder with uuid='{}' in namespace '{}' for integration '{}': {}",
                uuid,
                namespaceId.toStr(),
                integrationName,
                e.what())};
        }

        if (!nsReader->assetExistsByUUID(uuid))
        {
            return base::Error {
                fmt::format("Decoder '{}' (uuid='{}') does not exist in namespace '{}' for integration '{}'.",
                            decoderName,
                            uuid,
                            namespaceId.toStr(),
                            integrationName)};
        }
    }

    // KVDBs
    for (const auto& uuid : integration.getKVDBsByUUID())
    {
        std::string kvdbName;
        try
        {
            kvdbName = std::get<0>(nsReader->resolveNameFromUUID(uuid));
        }
        catch (const std::exception& e)
        {
            return base::Error {
                fmt::format("Failed to resolve name for KVDB with uuid='{}' in namespace '{}' for integration '{}': {}",
                            uuid,
                            namespaceId.toStr(),
                            integrationName,
                            e.what())};
        }

        try
        {
            (void)nsReader->getKVDBByUUID(uuid);
        }
        catch (const std::exception& e)
        {
            return base::Error {
                fmt::format("Error accessing KVDB '{}' (uuid='{}') in namespace '{}' for integration '{}': {}",
                            kvdbName,
                            uuid,
                            namespaceId.toStr(),
                            integrationName,
                            e.what())};
        }
    }

    // Category
    const auto& category = integration.getCategory();
    if (!cm::store::categories::exists(category))
    {
        return base::Error {fmt::format("Category '{}' is not a valid category for integration '{}' in namespace '{}'.",
                                        category,
                                        integrationName,
                                        namespaceId.toStr())};
    }

    // Default parent
    if (const auto& opt = integration.getDefaultParent(); opt.has_value())
    {
        const auto& parentName = *opt;
        if (!nsReader->assetExistsByUUID(parentName))
        {
            return base::Error {
                fmt::format("Default parent '{}' does not exist as asset in namespace '{}' for integration '{}'.",
                            std::get<0>(nsReader->resolveNameFromUUID(parentName)),
                            namespaceId.toStr(),
                            integrationName)};
        }
    }

    return base::noError();
}

base::OptError Builder::validateAsset(const std::shared_ptr<cm::store::ICMStoreNSReader>& nsReader,
                                      const json::Json& assetJson) const
{
    try
    {
        auto buildCtx = std::make_shared<builders::BuildCtx>();
        buildCtx->setRegistry(m_registry);
        buildCtx->setValidator(m_schema);
        buildCtx->setAllowedFields(m_allowedFields);
        buildCtx->setStoreNSReader(nsReader);

        auto assetBuilder = std::make_shared<policy::AssetBuilder>(buildCtx, m_definitionsBuilder);
        auto asset = (*assetBuilder)(assetJson);

        const auto& nsId = nsReader->getNamespaceId();
        const auto& assetName = asset.name();
        const auto& parents = asset.parents();

        for (const auto& parentName : parents)
        {
            if (!nsReader->assetExistsByName(parentName))
            {
                return base::Error {
                    fmt::format("Parent '{}' referenced by asset '{}' does not exist in namespace '{}'.",
                                parentName.toStr(),
                                assetName.toStr(),
                                nsId.toStr())};
            }
        }
    }
    catch (const std::exception& e)
    {
        return base::Error {e.what()};
    }

    return base::noError();
}

base::OptError Builder::softPolicyValidate(const std::shared_ptr<cm::store::ICMStoreNSReader>& nsReader,
                                           const cm::store::dataType::Policy& policy) const
{
    const auto& namespaceId = nsReader->getNamespaceId();
    const auto policyName = namespaceId.toStr();

    // Default parent
    const auto& defaultParent = policy.getDefaultParent();
    if (!nsReader->assetExistsByUUID(defaultParent))
    {
        return base::Error {fmt::format("Default parent '{}' does not exist as asset in policy '{}'.",
                                        std::get<0>(nsReader->resolveNameFromUUID(defaultParent)),
                                        policyName)};
    }

    // Root decoder optional
    const auto& defaultDecoder = policy.getRootDecoder();
    if (!nsReader->assetExistsByUUID(defaultDecoder))
    {
        return base::Error {fmt::format("Root decoder '{}' does not exist as asset in policy '{}'.",
                                        std::get<0>(nsReader->resolveNameFromUUID(defaultDecoder)),
                                        policyName)};
    }

    // Integrations
    for (const auto& integUUID : policy.getIntegrationsUUIDs())
    {
        std::string integrationName;
        try
        {
            const auto integration = nsReader->getIntegrationByUUID(integUUID);
            integrationName = integration.getName();
        }
        catch (const std::exception& e)
        {
            return base::Error {
                fmt::format("Failed to resolve integration with uuid='{}' referenced by policy '{}': {}",
                            integUUID,
                            policyName,
                            e.what())};
        }
    }

    return base::noError();
}
} // namespace builder
