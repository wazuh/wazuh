#ifndef _BUILDER2_BUILDER_HPP
#define _BUILDER2_BUILDER_HPP

#include <memory>

#include <builder/ibuilder.hpp>
#include <builder/ivalidator.hpp>
#include <schemf/ischema.hpp>
#include <store/istore.hpp>

namespace builder
{

class Builder final
    : public IBuilder
    , public IValidator
{
private:
    class StageRegistry;
    class OpRegistry;

    std::shared_ptr<store::IStore> m_storeRead; ///< Store reader interface
    std::shared_ptr<schemf::ISchema> m_schema;  ///< Schema interface

    std::shared_ptr<StageRegistry> m_stageRegistry; ///< Stage builders registry
    std::shared_ptr<OpRegistry> m_opRegistry;       ///< Operation builders registry

public:
    Builder() = default;
    ~Builder() = default;

    Builder(const std::shared_ptr<store::IStore>& storeRead, const std::shared_ptr<schemf::ISchema>& schema);

    base::RespOrError<std::shared_ptr<IPolicy>> buildPolicy(const base::Name& name) const override;
    base::RespOrError<base::Expression> buildAsset(const base::Name& name) const override;

    base::OptError validateIntegration(const json::Json& json) const override;
    base::OptError validateAsset(const json::Json& json) const override;
};

} // namespace builder

#endif // _BUILDER2_BUILDER_HPP
