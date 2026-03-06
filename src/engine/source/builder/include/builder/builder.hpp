#ifndef _BUILDER2_BUILDER_HPP
#define _BUILDER2_BUILDER_HPP

#include <memory>

#include <cmstore/icmstore.hpp>
#include <defs/idefinitions.hpp>
#include <geo/imanager.hpp>
#include <kvdbstore/ikvdbmanager.hpp>
#include <logpar/logpar.hpp>
#include <schemf/ischema.hpp>
#include <schemf/ivalidator.hpp>
#include <streamlog/ilogger.hpp>
#include <store/istore.hpp>
#include <wiconnector/iwindexerconnector.hpp>

#include <builder/iallowedFields.hpp>
#include <builder/ibuilder.hpp>
#include <builder/ivalidator.hpp>

namespace builder
{

/**
 * @brief External dependencies required by the Builder.
 */
struct BuilderDeps
{
    size_t logparDebugLvl = 0;                                       ///< Debug level for the log parser.
    std::shared_ptr<hlp::logpar::Logpar> logpar = nullptr;           ///< Log parser instance.
    std::shared_ptr<kvdbstore::IKVDBManager> kvdbManager;            ///< KVDB manager.
    std::shared_ptr<geo::IManager> geoManager;                       ///< Geo-location manager.
    std::shared_ptr<streamlog::ILogManager> logManager;              ///< Stream log manager.
    std::weak_ptr<wiconnector::IWIndexerConnector> iConnector;       ///< Wazuh-Indexer connector.
};

/**
 * @brief Concrete builder that builds policies and assets, and provides validation.
 *
 * Implements both IBuilder (build policies/assets) and IValidator (validate integrations/assets/policies).
 */
class Builder final
    : public IBuilder
    , public IValidator
{
private:
    class Registry;

    std::shared_ptr<cm::store::ICMStore> m_cmStore;                  ///< CMStore interface
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
    Builder(const std::shared_ptr<cm::store::ICMStore>& cmStore,
            const std::shared_ptr<schemf::IValidator>& schema,
            const std::shared_ptr<defs::IDefinitionsBuilder>& definitionsBuilder,
            const std::shared_ptr<IAllowedFields>& allowedFields,
            const BuilderDeps& builderDeps,
            const std::shared_ptr<::store::IStore>& store);

    /**
     * @copydoc IBuilder::buildPolicy
     */
    std::shared_ptr<IPolicy>
    buildPolicy(const cm::store::NamespaceId& namespaceId, bool trace = false, bool sandbox = false) const override;

    /**
     * @copydoc IBuilder::buildAsset
     */
    base::Expression buildAsset(const base::Name& name, const cm::store::NamespaceId& namespaceId) const override;

    /**
     * @copydoc IValidator::softIntegrationValidate
     */
    base::OptError softIntegrationValidate(const std::shared_ptr<cm::store::ICMStoreNSReader>& nsReader,
                                           const cm::store::dataType::Integration& integration) const override;

    /**
     * @copydoc IValidator::validateAsset
     */
    base::OptError validateAsset(const std::shared_ptr<cm::store::ICMStoreNSReader>& nsReader,
                                 const json::Json& assetJson) const override;

    /**
     * @copydoc IValidator::validateAssetShallow
     */
    base::OptError validateAssetShallow(const json::Json& assetJson) const override;

    /**
     * @copydoc IValidator::softPolicyValidate
     */
    base::OptError softPolicyValidate(const std::shared_ptr<cm::store::ICMStoreNSReader>& nsReader,
                                      const cm::store::dataType::Policy& policy) const override;
};

} // namespace builder

#endif // _BUILDER2_BUILDER_HPP
