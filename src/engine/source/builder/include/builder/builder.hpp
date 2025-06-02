#ifndef _BUILDER2_BUILDER_HPP
#define _BUILDER2_BUILDER_HPP

#include <memory>

#include <defs/idefinitions.hpp>
#include <geo/imanager.hpp>
// TODO: Until the indexer connector is unified with the rest of wazuh-manager
// #include <indexerConnector/iindexerconnector.hpp>
#include <kvdb/ikvdbmanager.hpp>
#include <logpar/logpar.hpp>
#include <schemf/ischema.hpp>
#include <schemf/ivalidator.hpp>
#include <store/istore.hpp>

#include <builder/iallowedFields.hpp>
#include <builder/ibuilder.hpp>
#include <builder/ivalidator.hpp>

namespace builder
{

struct BuilderDeps
{
    size_t logparDebugLvl = 0;
    std::shared_ptr<hlp::logpar::Logpar> logpar = nullptr;

    std::string kvdbScopeName;
    std::shared_ptr<kvdbManager::IKVDBManager> kvdbManager;
    std::shared_ptr<geo::IManager> geoManager;
    // std::shared_ptr<IIndexerConnector> iConnector;
};

class Builder final
    : public IBuilder
    , public IValidator
{
private:
    class Registry;

    std::shared_ptr<store::IStore> m_storeRead;                      ///< Store reader interface
    std::shared_ptr<schemf::IValidator> m_schema;                    ///< Schema validator
    std::shared_ptr<defs::IDefinitionsBuilder> m_definitionsBuilder; ///< Definitions builder
    std::shared_ptr<IAllowedFields> m_allowedFields; ///< Manages wich fields can be modified by different assets

    std::shared_ptr<Registry> m_registry; ///< builders registry

public:
    Builder() = default;
    ~Builder() = default;

    /**
     * @brief Construct a new Builder object
     *
     * @param storeRead Store reader interface
     * @param schema Schema validator
     * @param definitionsBuilder Definitions builder
     * @param allowedFields Manages wich fields can be modified by different assets
     * @param builderDeps Builders dependencies
     */
    Builder(const std::shared_ptr<store::IStore>& storeRead,
            const std::shared_ptr<schemf::IValidator>& schema,
            const std::shared_ptr<defs::IDefinitionsBuilder>& definitionsBuilder,
            const std::shared_ptr<IAllowedFields>& allowedFields,
            const BuilderDeps& builderDeps);

    /**
     * @copydoc IBuilder::buildPolicy
     */
    std::shared_ptr<IPolicy> buildPolicy(const base::Name& name,
                                         bool trace = false,
                                         bool sandbox = false,
                                         bool reverseOrderDecoders = false) const override;

    /**
     * @copydoc IBuilder::buildAsset
     */
    base::Expression buildAsset(const base::Name& name) const override;

    /**
     * @copydoc IBuilder::validateIntegration
     */
    base::OptError validateIntegration(const json::Json& json, const std::string& namespaceId) const override;

    /**
     * @copydoc IBuilder::validateAsset
     */
    base::OptError validateAsset(const json::Json& json) const override;

    /**
     * @copydoc IBuilder::validatePolicy
     */
    base::OptError validatePolicy(const json::Json& json) const override;
};

} // namespace builder

#endif // _BUILDER2_BUILDER_HPP
