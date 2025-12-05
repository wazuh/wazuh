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
 * Mirrors the logical catalog view: UUID, logical name and content hash.
 */
struct ResourceSummary
{
    std::string uuid; ///< Resource UUID (unique within namespace).
    std::string name; ///< Logical name, e.g. "decoder/apache_access".
    std::string hash; ///< Content hash (YAML or canonical representation).
};

/**
 * @brief High-level CRUD interface for Content Manager resources.
 *
 * Implementations are responsible for:
 *  - Resolving namespaces using cm::store::ICMStore.
 *  - Parsing resource documents (typically YAML) into the corresponding
 *    data types (Policy, Integration, KVDB, assets).
 *  - Delegating structural checks to an IContentValidator before mutating
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
     * @param nsName Namespace name.
     *
     * @throws std::runtime_error on invalid name, if the namespace already
     *         exists, or on storage errors.
     */
    virtual void createNamespace(std::string_view nsName) = 0;

    /**
     * @brief Delete an existing namespace and all of its resources.
     *
     * @param nsName Namespace name.
     *
     * @throws std::runtime_error if the namespace does not exist or the
     *         deletion cannot be completed.
     */
    virtual void deleteNamespace(std::string_view nsName) = 0;

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
     * @param nsName     Target namespace name.
     * @param document   Policy document (typically YAML).
     *
     * @throws std::runtime_error on parse errors, validation failures
     *         or storage errors.
     */
    virtual void upsertPolicy(std::string_view nsName, std::string_view document) = 0;

    /**
     * @brief Delete the policy of the given namespace.
     *
     * After this call, the namespace has no policy associated.
     *
     * @param nsName Target namespace name.
     *
     * @throws std::runtime_error if the namespace does not exist or the
     *         policy cannot be removed.
     */
    virtual void deletePolicy(std::string_view nsName) = 0;

    /***************************** Generic Resources **************************/

    /**
     * @brief List resources in a namespace by type.
     *
     * The result is a lightweight catalog view including UUID, logical
     * name and a content hash suitable for change tracking.
     *
     * @param nsName Target namespace name.
     * @param type   Resource type to list.
     *
     * @return List of resource summaries.
     *
     * @throws std::runtime_error if the namespace does not exist or the
     *         operation fails.
     */
    virtual std::vector<ResourceSummary> listResources(std::string_view nsName, cm::store::ResourceType type) const = 0;

    /**
     * @brief Get the serialized representation of a resource by UUID.
     *
     * The implementation must:
     *  - Resolve the UUID to its logical name and type.
     *  - Load the underlying object from the store.
     *  - Serialize it back to a document string (typically YAML).
     *
     * @param nsName Target namespace name.
     * @param uuid   Resource UUID.
     *
     * @return Document representing the resource.
     *
     * @throws std::runtime_error if the namespace or resource does not exist
     *         or if the serialization fails.
     */
    virtual std::string getResourceByUUID(std::string_view nsName, const std::string& uuid) const = 0;

    /**
     * @brief Upsert a resource (asset, integration or KVDB) from a document.
     *
     * The behavior depends on @p type:
     *  - For assets (DECODER, RULE, FILTER, OUTPUT):
     *      - The document is parsed into an internal asset representation.
     *  - For integrations:
     *      - The document is parsed into cm::store::dataType::Integration.
     *  - For KVDBs:
     *      - The document is parsed into cm::store::dataType::KVDB.
     *
     * @param nsName     Target namespace name.
     * @param type       Resource type.
     * @param document   Resource document (typically YAML).
     *
     * @throws std::runtime_error on parse errors, validation failures
     *         or storage errors.
     */
    virtual void upsertResource(std::string_view nsName, cm::store::ResourceType type, std::string_view document) = 0;

    /**
     * @brief Delete a resource by UUID.
     *
     * The implementation is expected to:
     *  - Resolve the UUID to its logical name and type.
     *  - Apply any business rules regarding deletions.
     *  - Remove the resource from the underlying store.
     *
     * @param nsName Target namespace name.
     * @param uuid   Resource UUID.
     *
     * @throws std::runtime_error if the namespace or resource does not exist
     *         or the deletion cannot be performed.
     */
    virtual void deleteResourceByUUID(std::string_view nsName, const std::string& uuid) = 0;
};

} // namespace cm::crud

#endif // _CM_CRUD_ICMCRUD_SERVICE_HPP
