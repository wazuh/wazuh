#include "builder.hpp"

#include <stdexcept>

#include <store/utils.hpp>

#include "builders/ibuildCtx.hpp"
#include "builders/registry.hpp"
#include "policy/assetBuilder.hpp"
#include "policy/policy.hpp"
#include "register.hpp"

namespace builder
{

class Builder::Registry final : public builders::RegistryType
{
};

Builder::Builder(const std::shared_ptr<store::IStore>& storeRead,
                 const std::shared_ptr<schemf::ISchema>& schema,
                 const std::shared_ptr<defs::IDefinitionsBuilder>& definitionsBuilder,
                 const std::shared_ptr<schemval::IValidator>& validator,
                 const BuilderDeps& builderDeps)
    : m_storeRead {storeRead}
    , m_schema {schema}
    , m_validator {validator}
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

    if (!m_validator)
    {
        throw std::runtime_error {"Validator is null"};
    }

    // Registry
    m_registry = std::static_pointer_cast<Registry>(Registry::create<builders::Registry>());

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
        base::getResponse<store::Doc>(policyDoc), m_storeRead, m_definitionsBuilder, m_registry, m_validator);

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
    buildCtx->setValidator(m_validator);
    buildCtx->runState().trace = true;

    auto assetBuilder = std::make_shared<policy::AssetBuilder>(buildCtx, m_definitionsBuilder);
    auto asset = (*assetBuilder)(base::getResponse<store::Doc>(assetDoc));

    return asset.expression();
}

base::OptError Builder::validateIntegration(const json::Json& json) const
{
    return base::Error {"Not implemented"};
}

base::OptError Builder::validateAsset(const json::Json& json) const
{
    try
    {
        auto buildCtx = std::make_shared<builders::BuildCtx>();
        buildCtx->setRegistry(m_registry);
        buildCtx->setValidator(m_validator);
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
    // TODO: handle empty policies and missing assets
    // try
    // {
    //     auto policy = std::make_shared<policy::Policy>(json, m_storeRead, m_definitionsBuilder, m_registry);
    // }
    // catch (const std::exception& e)
    // {
    //     return base::Error {e.what()};
    // }

    return base::noError();
}
} // namespace builder
