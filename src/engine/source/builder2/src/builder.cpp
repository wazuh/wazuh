#include "builder.hpp"

#include <stdexcept>

#include "builders/types.hpp"
#include "policy/policy.hpp"
#include "register.hpp"
#include "registry/registry.hpp"

namespace builder
{
struct StageBuilder // TODO
{
};

class Builder::StageRegistry final : public registry::Registry<StageBuilder>
{
};

class Builder::OpRegistry final : public registry::Registry<builders::OpBuilder>
{
};

Builder::Builder(const std::shared_ptr<store::IStore>& storeRead, const std::shared_ptr<schemf::ISchema>& schema)
    : m_storeRead {storeRead}
    , m_schema {schema}
    , m_stageRegistry {std::make_shared<StageRegistry>()}
    , m_opRegistry {std::make_shared<OpRegistry>()}
{
    if (!m_storeRead)
    {
        throw std::runtime_error {"Store reader interface is null"};
    }

    if (!m_schema)
    {
        throw std::runtime_error {"Schema interface is null"};
    }

    // Register all the builders
    // detail::registerStageBuilders<Builder>(m_stageRegistry);
    detail::registerOpBuilders<builders::OpBuilder>(m_opRegistry);
}

base::RespOrError<std::shared_ptr<IPolicy>> Builder::buildPolicy(const base::Name& name) const
{
    auto policyDoc = m_storeRead->readInternalDoc(name);
    if (base::isError(policyDoc))
    {
        throw std::runtime_error(base::getError(policyDoc).message);
    }

    return std::make_shared<policy::Policy>(base::getResponse<store::Doc>(policyDoc), m_storeRead);
}

base::RespOrError<base::Expression> Builder::buildAsset(const base::Name& name) const
{
    return base::Error {"Not implemented"};
}

base::OptError Builder::validateIntegration(const json::Json& json) const
{
    return base::OptError {};
}

base::OptError Builder::validateAsset(const json::Json& json) const
{
    return base::OptError {};
}

} // namespace builder
