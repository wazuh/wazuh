#ifndef _BUILDER2_BUILDER_HPP
#define _BUILDER2_BUILDER_HPP

#include <memory>

#include <defs/idefinitions.hpp>
#include <kvdb/ikvdbmanager.hpp>
#include <logpar/logpar.hpp>
#include <schemf/ischema.hpp>
#include <schemval/ivalidator.hpp>
#include <sockiface/isockFactory.hpp>
#include <store/istore.hpp>
#include <wdb/iwdbManager.hpp>

#include <builder/ibuilder.hpp>
#include <builder/ivalidator.hpp>

namespace builder
{

struct BuilderDeps
{
    size_t logparDebugLvl = 0;
    std::shared_ptr<hlp::logpar::Logpar> logpar = nullptr;
    // TODO: add other dependencies
    std::string kvdbScopeName;
    std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager;
    std::shared_ptr<sockiface::ISockFactory> sockFactory;
    std::shared_ptr<wazuhdb::IWDBManager> wdbManager;
    // std::shared_ptr<Registry<HelperBuilder>> helperRegistry;
    // std::shared_ptr<schemf::ISchema> schema;
    // bool forceFieldNaming = false;
};

class Builder final
    : public IBuilder
    , public IValidator
{
private:
    class Registry;

    std::shared_ptr<store::IStore> m_storeRead;                      ///< Store reader interface
    std::shared_ptr<schemf::ISchema> m_schema;                       ///< Schema interface
    std::shared_ptr<schemval::IValidator> m_validator;               ///< Schema validator
    std::shared_ptr<defs::IDefinitionsBuilder> m_definitionsBuilder; ///< Definitions builder

    std::shared_ptr<Registry> m_registry; ///< builders registry

public:
    Builder() = default;
    ~Builder() = default;

    Builder(const std::shared_ptr<store::IStore>& storeRead,
            const std::shared_ptr<schemf::ISchema>& schema,
            const std::shared_ptr<defs::IDefinitionsBuilder>& definitionsBuilder,
            const std::shared_ptr<schemval::IValidator>& validator,
            const BuilderDeps& builderDeps);

    std::shared_ptr<IPolicy> buildPolicy(const base::Name& name) const override;
    base::Expression buildAsset(const base::Name& name) const override;

    base::OptError validateIntegration(const json::Json& json) const override;
    base::OptError validateAsset(const json::Json& json) const override;
    base::OptError validatePolicy(const json::Json& json) const override;
};

} // namespace builder

#endif // _BUILDER2_BUILDER_HPP
