#include "builder.hpp"

#include <stdexcept>

#include <store/utils.hpp>

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

Builder::Builder(const std::shared_ptr<store::IStore>& storeRead,
                 const std::shared_ptr<schemf::IValidator>& schema,
                 const std::shared_ptr<defs::IDefinitionsBuilder>& definitionsBuilder,
                 const BuilderDeps& builderDeps)
    : m_storeRead {storeRead}
    , m_schema {schema}
    , m_definitionsBuilder {definitionsBuilder}
{
    if (!m_storeRead)
    {
        throw std::runtime_error {"Store reader interface is null"};
    }

    if (!m_schema)
    {
        throw std::runtime_error {"Schema interface is null"};
    }

    if (!m_definitionsBuilder)
    {
        throw std::runtime_error {"Definitions builder is null"};
    }

    // Registry
    m_registry = std::static_pointer_cast<Registry>(Registry::create<builder::Registry>());

    detail::registerStageBuilders<Registry>(m_registry, builderDeps);
    detail::registerOpBuilders<Registry>(m_registry, builderDeps);
}

std::shared_ptr<IPolicy> Builder::buildPolicy(const base::Name& name) const
{
    auto policyDoc = m_storeRead->readInternalDoc(name);
    if (base::isError(policyDoc))
    {
        throw std::runtime_error(base::getError(policyDoc).message);
    }

    auto policy = std::make_shared<policy::Policy>(
        base::getResponse<store::Doc>(policyDoc), m_storeRead, m_definitionsBuilder, m_registry, m_schema);

    return policy;
}

base::Expression Builder::buildAsset(const base::Name& name) const
{
    auto assetDoc = store::utils::get(m_storeRead, name);
    if (base::isError(assetDoc))
    {
        throw std::runtime_error(base::getError(assetDoc).message);
    }

    auto buildCtx = std::make_shared<builders::BuildCtx>();
    buildCtx->setRegistry(m_registry);
    buildCtx->setValidator(m_schema);
    buildCtx->runState().trace = true;

    auto assetBuilder = std::make_shared<policy::AssetBuilder>(buildCtx, m_definitionsBuilder);
    auto asset = (*assetBuilder)(base::getResponse<store::Doc>(assetDoc));

    return asset.expression();
}

base::OptError Builder::validateIntegration(const json::Json& json, const std::string& namespaceId) const
{
    // TODO: Make factory so this can be implemented without duplicating code
    policy::factory::PolicyData policyData;
    try
    {
        policyData = policy::factory::PolicyData({.name = "policy/fake/0", .hash = "fakehash"});
    }
    catch (const std::exception& e)
    {
        return base::Error {fmt::format("Error creating dummy policy: {}", e.what())};
    }

    auto namePath = json::Json::formatJsonPath(syntax::asset::NAME_KEY);
    auto integrationNameResp = json.getString(namePath);
    if (!integrationNameResp)
    {
        return base::Error {"Integration name not found"};
    }
    auto integrationName = integrationNameResp.value();
    try
    {
        policy::factory::addIntegrationSubgraph(policy::factory::PolicyData::AssetType::DECODER,
                                                syntax::integration::DECODER_PATH,
                                                json,
                                                m_storeRead,
                                                integrationName,
                                                namespaceId,
                                                policyData);
        policy::factory::addIntegrationSubgraph(policy::factory::PolicyData::AssetType::RULE,
                                                syntax::integration::RULE_PATH,
                                                json,
                                                m_storeRead,
                                                integrationName,
                                                namespaceId,
                                                policyData);
        policy::factory::addIntegrationSubgraph(policy::factory::PolicyData::AssetType::OUTPUT,
                                                syntax::integration::OUTPUT_PATH,
                                                json,
                                                m_storeRead,
                                                integrationName,
                                                namespaceId,
                                                policyData);
    }
    catch (const std::exception& e)
    {
        return base::Error {e.what()};
    }

    auto buildCtx = std::make_shared<builders::BuildCtx>();
    buildCtx->setRegistry(m_registry);
    buildCtx->setValidator(m_schema);
    buildCtx->runState().trace = true;

    auto assetBuilder = std::make_shared<policy::AssetBuilder>(buildCtx, m_definitionsBuilder);

    try
    {
        policy::factory::buildAssets(policyData, m_storeRead, assetBuilder);
    }
    catch (const std::exception& e)
    {
        return base::Error {e.what()};
    }

    return base::noError();
}

base::OptError Builder::validateAsset(const json::Json& json) const
{
    try
    {
        auto buildCtx = std::make_shared<builders::BuildCtx>();
        buildCtx->setRegistry(m_registry);
        buildCtx->setValidator(m_schema);
        auto assetBuilder = std::make_shared<policy::AssetBuilder>(buildCtx, m_definitionsBuilder);
        auto asset = (*assetBuilder)(json);
    }
    catch (const std::exception& e)
    {
        return base::Error {e.what()};
    }

    return base::noError();
}

base::OptError Builder::validatePolicy(const json::Json& json) const
{
    try
    {
        auto policy = std::make_shared<policy::Policy>(json, m_storeRead, m_definitionsBuilder, m_registry, m_schema);
    }
    catch (const std::exception& e)
    {
        return base::Error {e.what()};
    }

    return base::noError();
}
} // namespace builder
