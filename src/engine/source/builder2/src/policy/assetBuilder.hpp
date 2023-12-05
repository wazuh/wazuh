#ifndef _BUILDER_POLICY_ASSETBUILDER_HPP
#define _BUILDER_POLICY_ASSETBUILDER_HPP

#include <defs/idefinitions.hpp>

#include "builders/buildCtx.hpp"
#include "builders/iregistry.hpp"
#include "iassetBuilder.hpp"

namespace builder::policy
{

class AssetBuilder : public IAssetBuilder
{
private:
    std::shared_ptr<builders::BuildCtx> m_buildCtx;
    std::shared_ptr<defs::IDefinitionsBuilder> m_definitionsBuilder;

public:
    AssetBuilder(const std::shared_ptr<builders::BuildCtx>& buildCtx,
                 const std::shared_ptr<defs::IDefinitionsBuilder>& definitionsBuilder)
        : m_buildCtx(buildCtx)
        , m_definitionsBuilder(definitionsBuilder)
    {
    }

    base::Name getName(const json::Json& value) const;
    std::vector<base::Name> getParents(const json::Json& value) const;
    base::Expression buildExpression(const base::Name& name, std::vector<std::tuple<std::string, json::Json>>& objDoc) const;

    Asset operator()(const store::Doc& document) const override;
};

} // namespace builder::policy

#endif // _BUILDER_POLICY_ASSETBUILDER_HPP
