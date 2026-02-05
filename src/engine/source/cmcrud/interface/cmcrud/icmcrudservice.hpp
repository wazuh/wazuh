#ifndef _CM_CRUD_ICMCRUD_SERVICE_HPP
#define _CM_CRUD_ICMCRUD_SERVICE_HPP

#include <string>
#include <string_view>
#include <vector>

#include <base/json.hpp>
#include <cmstore/icmstore.hpp>

namespace cm::crud
{

/**
 * @brief Small summary of a resource in a namespace.
 *
 * Mirrors the logical catalog view: UUID and logical name.
 */
struct ResourceSummary
{
    std::string uuid; ///< Resource UUID (unique within namespace).
    std::string name; ///< Logical name, e.g. "decoder/apache_access".
};

/**
 * @brief High-level CRUD interface for Content Manager resources.
 *
 * Implementations are responsible for:
 *  - Resolving namespaces using cm::store::ICMStore.
 *  - Parsing resource documents (typically YAML) into the corresponding
 *    data types (Policy, Integration, KVDB, assets).
 *  - Delegating structural checks to an builder::IValidator before mutating
 *    the underlying store.
 *  - Applying the cm::store mutations on success.
 *
 * Error handling:
 *  - Implementations are expected to signal failures by throwing
 *    std::runtime_error (or a derived type) with a descriptive message.
 */
class ICrudService
{
public:
    virtual ~ICrudService() = default;

    /******************************* Namespaces *******************************/

    /**
     * @brief List all existing namespaces.
     *
     * @return List of NamespaceId objects representing all known namespaces.
     */
    virtual std::vector<cm::store::NamespaceId> listNamespaces() const = 0;

    /**
     * @brief Create a new namespace.
     *
     * If the namespace already exists, the implementation should fail.
     *
     * @param nsId Namespace identifier.
     *
     * @throws std::runtime_error on invalid name, if the namespace already
     *         exists, or on storage errors.
     */
    virtual void createNamespace(const cm::store::NamespaceId& nsId) = 0;

    /**
     * @brief Check if a namespace exists.
     *
     * @param nsId Namespace identifier.
     * @return true if the namespace exists, false otherwise.
     */
    virtual bool existsNamespace(const cm::store::NamespaceId& nsId) const = 0;

    /**
     * @brief Delete an existing namespace and all of its resources.
     *
     * @param nsId Namespace identifier.
     *
     * @throws std::runtime_error if the namespace does not exist or the
     *         deletion cannot be completed.
     */
    virtual void deleteNamespace(const cm::store::NamespaceId& nsId) = 0;

    /*
     * @brief Import a full namespace from a JSON document in a new namespace.
     *
     * The document is expected to contain a full representation of the policy
     * and resources to be imported into the new namespace. The structure must be:
     * {
     *  "resources": {
     *    "kvdbs": [ ... ],     // Array of KVDB objects
     *    "decoders": [ ... ],  // Array of decoder objects
     *    "integrations": [ ... ], // Array of integration objects
     *    "policy": { ... }        // Policy object
     * }
     *
     * @param nsId Namespace identifier, to store the imported data.
     * @param jsonDocument JSON string with policy + resources. must end in \0
     * @param origin Origin space name for the imported namespace.
     * @param force If true, skip all validations.
     * @throws std::runtime_error on errors.
     * TODO: Change jsonDocument from string_view to json::Json
     */
    virtual void importNamespace(const cm::store::NamespaceId& nsId,
                                 std::string_view jsonDocument,
                                 std::string_view origin,
                                 bool force) = 0;

    /**
     * @brief Import a full namespace from individual components.
     *
     * @param nsName Namespace identifier, to store the imported data.
     * @param kvdbs list of KVDB definitions in json format
     * @param decoders list of decoder definitions in json format
     * @param integrations list of integration definitions in json format
     * @param policy policy definition in json format
     * @param softValidation if true, only check the most critical validations.
     * @throws std::runtime_error on errors.
     */
    virtual void importNamespace(const cm::store::NamespaceId& nsId,
                                 const std::vector<json::Json>& kvdbs,
                                 const std::vector<json::Json>& decoders,
                                 const std::vector<json::Json>& integrations,
                                 const json::Json& policy,
                                 bool softValidation) = 0;

    /********************************* Policy *********************************/

    /**
     * @brief Upsert the policy associated to a namespace from a document.
     *
     * Behavior:
     *  - If the namespace has no policy, a new one is created.
     *  - If it already has one, it is replaced.
     *  - The document is parsed into cm::store::dataType::Policy.
     *  - The resulting policy is validated before being stored.
     *
     * @param nsId       Target namespace identifier.
     * @param document   Policy document (typically YAML).
     *
     * @throws std::runtime_error on parse errors, validation failures
     *         or storage errors.
     */
    virtual void upsertPolicy(const cm::store::NamespaceId& nsId, std::string_view document) = 0;

    /**
     * @brief Delete the policy of the given namespace.
     *
     * After this call, the namespace has no policy associated.
     *
     * @param nsId Target namespace identifier.
     *
     * @throws std::runtime_error if the namespace does not exist or the
     *         policy cannot be removed.
     */
    virtual void deletePolicy(const cm::store::NamespaceId& nsId) = 0;

    /***************************** Generic Resources **************************/

    /**
     * @brief List resources in a namespace by type.
     *
     * The result is a lightweight catalog view including UUID and logical name.
     *
     * @param nsId   Target namespace identifier.
     * @param type   Resource type to list.
     *
     * @return List of resource summaries.
     *
     * @throws std::runtime_error if the namespace does not exist or the
     *         operation fails.
     */
    virtual std::vector<ResourceSummary> listResources(const cm::store::NamespaceId& nsId,
                                                       cm::store::ResourceType type) const = 0;

    /**
     * @brief Get the serialized representation of a resource by UUID.
     *
     * The implementation must:
     *  - Resolve the UUID to its logical name and type.
     *  - Load the underlying object from the store.
     *  - Serialize it back to a document string (typically YAML).
     *
     * @param nsId   Target namespace identifier.
     * @param uuid   Resource UUID.
     * @param asJSon Get with json format
     *
     * @return Document representing the resource.
     *
     * @throws std::runtime_error if the namespace or resource does not exist
     *         or if the serialization fails.
     */
    virtual std::string
    getResourceByUUID(const cm::store::NamespaceId& nsId, const std::string& uuid, bool asJson) const = 0;

    /**
     * @brief Upsert a resource (asset, integration or KVDB) from a document.
     *
     * The behavior depends on @p type:
     *  - For assets (DECODER, FILTER, OUTPUT):
     *      - The document is parsed into an internal asset representation.
     *  - For integrations:
     *      - The document is parsed into cm::store::dataType::Integration.
     *  - For KVDBs:
     *      - The document is parsed into cm::store::dataType::KVDB.
     *
     * @param nsId       Target namespace identifier.
     * @param type       Resource type.
     * @param document   Resource document (typically YAML).
     *
     * @throws std::runtime_error on parse errors, validation failures
     *         or storage errors.
     */
    virtual void
    upsertResource(const cm::store::NamespaceId& nsId, cm::store::ResourceType type, std::string_view document) = 0;

    /**
     * @brief Delete a resource by UUID.
     *
     * The implementation is expected to:
     *  - Resolve the UUID to its logical name and type.
     *  - Apply any business rules regarding deletions.
     *  - Remove the resource from the underlying store.
     *
     * @param nsId   Target namespace identifier.
     * @param uuid   Resource UUID.
     *
     * @throws std::runtime_error if the namespace or resource does not exist
     *         or the deletion cannot be performed.
     */
    virtual void deleteResourceByUUID(const cm::store::NamespaceId& nsId, const std::string& uuid) = 0;

    /**
     * @brief Validate a resource payload (isolated, no namespace).
     *
     * The implementation must:
     *  - Parse @p document as JSON.
     *  - Validate the resource structure according to @p type.
     *
     * Notes:
     *  - For DECODER validation, missing KVDB references must NOT be treated as an error.
     *
     * @param type         Resource type to validate.
     * @param document Resource document as JSON string.
     *
     * @throws std::runtime_error on parse errors or validation failures.
     */
    virtual void validateResource(cm::store::ResourceType type, const json::Json& payload) = 0;
};

} // namespace cm::crud

#endif // _CM_CRUD_ICMCRUD_SERVICE_HPP
