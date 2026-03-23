#ifndef _BUILDER2_IVALIDATOR_HPP
#define _BUILDER2_IVALIDATOR_HPP

#include <base/error.hpp>
#include <base/json.hpp>
#include <cmstore/icmstore.hpp>

namespace builder
{

/**
 * @brief Builder-facing validation interface used by the CM CRUD layer.
 */
class IValidator
{
public:
    virtual ~IValidator() = default;

    /**
     * @brief Validate an Integration.
     *
     * Implementation may:
     *  - Check that all referenced decoders and KVDBs exist in the namespace.
     *  - Check that the category is valid.
     *  - Check that the default_parent (if any) exists and is of the correct type.
     *
     * @param nsReader Namespace reader used to resolve and verify references.
     * @param integration Parsed integration definition (schema already validated upstream).
     * @return base::OptError Empty on success, otherwise an error describing the first failure found.
     */
    virtual base::OptError softIntegrationValidate(const std::shared_ptr<cm::store::ICMStoreNSReader>& nsReader,
                                                   const cm::store::dataType::Integration& integration) const = 0;

    /**
     * @brief Fully validate an Asset including dependency checks (namespace-aware).
     *
     * Implementation may:
     *  - Check that all dependencies referenced by the asset exist in the namespace.
     *  - Check that the asset structure is valid according to its type.
     *
     * @param nsReader Namespace reader used to verify parent dependencies.
     * @param assetJson Asset JSON definition (already parsed from YAML/JSON by upper layers).
     * @return base::OptError Empty on success, otherwise an error describing the failure.
     */
    virtual base::OptError validateAsset(const std::shared_ptr<cm::store::ICMStoreNSReader>& nsReader,
                                         const json::Json& assetJson) const = 0;

    /**
     * @brief Shallow validate an Asset without resolving dependencies.
     *
     * Implementation may:
     *  - Check that the asset structure is valid according to its type.
     *  - To decoders, ensure that KVDB references are UUIDv4 formatted, but do NOT check existence.
     *
     * @param assetJson Asset JSON definition.
     * @return base::OptError Empty on success, otherwise an error describing the failure.
     */
    virtual base::OptError validateAssetShallow(const json::Json& assetJson) const = 0;

    /**
     * @brief Validate a Policy against the namespace (semantic checks).
     *
     * Implementation may:
     *  - Check that all referenced integrations exist in the namespace.
     *  - Check that the default_parent and root_decoder (if any) exist and are of the correct type.
     *
     * @param nsReader Namespace reader used to resolve and verify references.
     * @param policy Parsed policy definition (schema already validated upstream).
     * @return base::OptError Empty on success, otherwise an error describing the first failure found.
     */
    virtual base::OptError softPolicyValidate(const std::shared_ptr<cm::store::ICMStoreNSReader>& nsReader,
                                              const cm::store::dataType::Policy& policy) const = 0;
};

} // namespace builder

#endif // _BUILDER2_IVALIDATOR_HPP
