#ifndef DNM_IDOCUMENT_MANAGER_HPP
#define DNM_IDOCUMENT_MANAGER_HPP

#include <list>
#include <optional>
#include <string>
#include <utility>
#include <variant>

#include <error.hpp>
#include <json/json.hpp>
#include <name.hpp>

#include "types.hpp"

/**
 * @brief Document Namespace Manager Interface
 *
 * Manages the document storage and namespaces, which are used to group documents together
 * The document name (virtual name) are unique regardless of the namespace.
 * The namespace is used to group documents together, a document must be assigned to a namespace.
 *
 * The Key (base::Name) is used to identify a document or collection in the store.
 */
namespace dnm
{

/**
 * @brief Document Namespace reader interface
 *
 * This interface is used to read the document store:
 * - Get the namespace identifier of a document.
 * - Get a document from the store.
 * - Get a list of documents from a namespace.
 * - List documents and collections under a Key.
 * - Check if a Key is a document or a collection.
 * - List all namespaces.
 * - List all documents.
 */
class INamespacesReader
{
protected:
    INamespacesReader() = default;

public:
    /**
     * @brief Get the namespace identifier of a document.
     * @param key The document key.
     * @return The namespace identifier or error if the document does not exist or is a collection.
     */
    virtual std::optional<NamespaceID> getNamespace(const base::Name& key) const = 0;

    /**
     * @brief Get a document from the store.
     * @param key The document key.
     * @return The document or error if the document does not exist or is a collection.
     */
    virtual std::variant<json::Json, base::Error> getDocument(const base::Name& key) const = 0;

    /**
     * @brief Get a list of namespaces with documents.
     *
     * @return The list of namespaces.
     */
    virtual std::vector<NamespaceID> listNamespaces() const = 0;

    /**
     * @brief Get a list of documents key from a namespace. [Docs Filter by namespace]
     * @param namespaceID The namespace identifier.
     * @return The list of documents or nullopt if the namespace does not exist.
     */
    virtual std::optional<std::vector<base::Name>> listDocuments(const NamespaceID& namespaceID) const = 0;

    /**
     * @brief List documents and collections (keys) under a Key.
     *
     * THe depth is limited to 1 and the key returned are absolute. [Docs Filter by key]
     * @param key The key to list.
     * @return The list of documents and collections or nullopt if the key does not exist.
     */
    virtual std::optional<std::vector<std::pair<base::Name, KeyType>>> list(const base::Name& key) const = 0;

    /**
     * @brief List documents and collections (keys) under a Key, filtered by namespace.
     *
     * The depth is limited to 1 and the key returned are absolute. [Docs Filter by namespace and key]
     * @param key The key to list.
     * @return The list of documents and collections or nullopt if the key does not exist.
     */
    virtual std::optional<std::vector<std::pair<base::Name, KeyType>>> list(const base::Name& key,
                                                                            const NamespaceID& namespaceID) const = 0;

    /**
     * @brief Check if a Key is a document or a collection.
     * @param key The key to check.
     * @return The key type or nullopt if the key does not exist.
     */
    virtual std::optional<KeyType> getType(const base::Name& key) const = 0;
};

/**
 * @brief Document Manager Interface
 *
 * This interface is used to manage the document store:
 * - Add a document to the store.
 * - Remove a document from the store.
 * - Update a document in the store.
 * - Upsert a document in the store.
 */
class IDocumentManager : public INamespacesReader
{
protected:
    IDocumentManager() = default;

public:
    /**
     * @brief Add a document to the store.
     *
     * If the document already exists, the document is not added and the function returns error.
     * @param key The document key.
     * @param json::Json The document to add.
     * @param namespaceID The namespace identifier.
     * @return std::optional<base::Error> An error if the operation failed.
     */
    virtual std::optional<base::Error>
    add(const base::Name& key, const json::Json& document, const NamespaceID& namespaceID) = 0;

    /**
     * @brief Remove a document from the store.
     *
     * If the document does not exist, the function returns error.
     * @param key The document key.
     * @return std::optional<base::Error> An error if the operation failed.
     */
    virtual std::optional<base::Error> remove(const base::Name& key) = 0;

    /**
     * @brief Update a document in the store.
     *
     * If the document does not exist, the function returns error.
     * @param key The document key.
     * @param json::Json The document to update.
     * @return std::optional<base::Error> An error if the operation failed.
     */
    virtual std::optional<base::Error> update(const base::Name& key, const json::Json& document) = 0;

    /**
     * @brief Upsert a document in the store.
     *
     * If the document does not exist, the document is added.
     * If the document already exists, the document is updated.
     * If the document already exists and has a different namespace, the function returns error.
     * @param key The document key.
     * @param json::Json The document to upsert.
     * @param namespaceID The namespace identifier.
     * @return std::optional<base::Error> An error if the operation failed.
     */
    virtual std::optional<base::Error>
    upsert(const base::Name& key, const json::Json& document, const NamespaceID& namespaceID) = 0;
};

} // namespace dnm

#endif // DNM_IDOCUMENT_MANAGER_HPP
