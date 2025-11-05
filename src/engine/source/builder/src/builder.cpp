#include "builder.hpp"

#include <stdexcept>

#include <store/utils.hpp>

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

Builder::Builder(const std::shared_ptr<cm::store::ICMstore>& cmStore,
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

base::OptError Builder::validateIntegration(const base::Name& name, const cm::store::NamespaceId& namespaceId) const
{
    const auto nsReader = m_cmStore->getNSReader(namespaceId);
    const auto& integration = nsReader->getIntegrationByName(name);
    for (const auto& uuid : integration.getDecodersByUUID())
    {
        if (!nsReader->assetExistsByUUID(uuid))
        {
            return base::Error {fmt::format("Decoder UUID '{}' does not exist in the namespace.", uuid)};
        }
    }

    for (const auto& uuid : integration.getKVDBsByUUID())
    {
        if (!nsReader->kvdbExistsByUUID(uuid))
        {
            return base::Error {fmt::format("KVDB UUID '{}' does not exist in the namespace.", uuid)};
        }
    }

    if (const auto& opt = integration.getDefaultParent(); opt.has_value())
    {
        const base::Name& parentName = *opt;
        if (!nsReader->assetExistsByName(parentName))
        {
            return base::Error {fmt::format("Default parent '{}' does not exist as asset.", parentName.toStr())};
        }
    }

    return base::noError();
}

base::OptError Builder::validateAsset(const base::Name& name, const cm::store::NamespaceId& namespaceId) const
{
    try
    {
        auto buildCtx = std::make_shared<builders::BuildCtx>();
        buildCtx->setRegistry(m_registry);
        buildCtx->setValidator(m_schema);
        buildCtx->setAllowedFields(m_allowedFields);
        auto assetBuilder = std::make_shared<policy::AssetBuilder>(buildCtx, m_definitionsBuilder);

        const auto nsReader = m_cmStore->getNSReader(namespaceId);
        const auto& jsonAsset = nsReader->getAssetByName(name);
        auto asset = (*assetBuilder)(jsonAsset);
    }
    catch (const std::exception& e)
    {
        return base::Error {e.what()};
    }

    return base::noError();
}

base::OptError Builder::validatePolicy(const cm::store::NamespaceId& namespaceId) const
{
    try
    {
        auto policy = std::make_shared<policy::Policy>(
            namespaceId, m_cmStore, m_definitionsBuilder, m_registry, m_schema, m_allowedFields);
    }
    catch (const std::exception& e)
    {
        return base::Error {e.what()};
    }

    return base::noError();
}
} // namespace builder
