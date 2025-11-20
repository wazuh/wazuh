#ifndef _CM_CRUD_ICONTENT_VALIDATOR_HPP
#define _CM_CRUD_ICONTENT_VALIDATOR_HPP

#include <string_view>

#include <base/json.hpp>
#include <base/name.hpp>

#include <cmstore/icmstore.hpp>

namespace cm::crud
{

/**
 * @brief Validation interface for Content Manager resources.
 *
 * Implementations are responsible for checking that a given resource
 * (policy, integration, KVDB, asset) is structurally valid and consistent
 * with the current state of a namespace.
 *
 * Typical responsibilities:
 *  - Verify references to other resources inside the same namespace.
 *  - Enforce uniqueness and immutability rules for identifiers.
 *  - Perform structural checks on the payloads.
 *
 * Error handling:
 *  - Implementations are expected to signal validation failures by throwing
 *    std::runtime_error (or a derived type) with a descriptive message.
 */
class IContentValidator
{
public:
    virtual ~IContentValidator() = default;

    /**
     * @brief Validate a namespace.
     *
     * Typical checks may include:
     *  - Non-empty name.
     *  - Reservation rules (e.g. writable vs read-only namespaces).
     *
     * @param nsName Namespace name to validate.
     *
     * @throws std::runtime_error if the namespace name is invalid.
     */
    virtual void validateNamespace(std::string_view nsName) const = 0;

    /**
     * @brief Validate a Policy object for the namespace represented by @p nsReader.
     *
     * Implementations may:
     *  - Ensure that root_decoder exists.
     *  - Ensure that referenced integrations exist.
     *
     * @param nsReader Read-only view of the namespace contents.
     * @param policy   Policy object to validate.
     *
     * @throws std::runtime_error if the policy is invalid.
     */
    virtual void validatePolicy(const std::shared_ptr<cm::store::ICMStoreNSReader>& nsReader,
                                const cm::store::dataType::Policy& policy) const = 0;

    /**
     * @brief Validate an Integration object for the namespace represented by @p nsReader.
     *
     * Implementations may:
     *  - Check that category is valid and exists.
     *  - Ensure that default_parent exists.
     *  - Ensure that referenced KVDBs exist.
     *  - Enforce name / UUID consistency rules.
     *  - Ensure that decoders exist in the store.
     *
     * @param nsReader   Read-only view of the namespace contents.
     * @param integration Integration object to validate.
     *
     * @throws std::runtime_error if the integration is invalid.
     */
    virtual void validateIntegration(const std::shared_ptr<cm::store::ICMStoreNSReader>& nsReader,
                                     const cm::store::dataType::Integration& integration) const = 0;

    /**
     * @brief Validate a KVDB object for the namespace represented by @p nsReader.
     *
     * Implementations may:
     *  - Check name / UUID semantics.
     *  - Enforce structural constraints on the KVDB document.
     *
     * @param nsReader Read-only view of the namespace contents.
     * @param kvdb     KVDB object to validate.
     *
     * @throws std::runtime_error if the KVDB is invalid.
     */
    virtual void validateKVDB(const std::shared_ptr<cm::store::ICMStoreNSReader>& nsReader,
                              const cm::store::dataType::KVDB& kvdb) const = 0;

    /**
     * @brief Validate an asset (decoder, rule, filter, output) for the namespace.
     *
     * Implementations may:
     * - Enforce structural constraints on the asset document.
     * - Ensure that the asset can be built.
     * - Check that exists in builder.
     *
     * @param nsReader Read-only view of the namespace contents.
     * @param name     Logical asset name as base::Name.
     * @param asset    Canonical JSON representation of the asset after YAML parsing.
     *
     * @throws std::runtime_error if the asset is invalid.
     */
    virtual void validateAsset(const std::shared_ptr<cm::store::ICMStoreNSReader>& nsReader,
                               const base::Name& name,
                               const json::Json& asset) const = 0;
};

} // namespace cm::crud

#endif // _CM_CRUD_ICONTENT_VALIDATOR_HPP
