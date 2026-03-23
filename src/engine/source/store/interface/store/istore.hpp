#ifndef _STORE_ISTORE_HPP
#define _STORE_ISTORE_HPP

#include <list>
#include <string>
#include <utility>

#include <store/idriver.hpp>

/**
 * @brief Document Store Interface
 *
 * Manages the document storage using a key-value approach.
 * The Key (base::Name) is used to identify a document or collection in the store.
 */
namespace store
{

/**
 * @brief Document store interface.
 */
class IStore
{
public:
    virtual ~IStore() = default;

    /**
     * @brief Create a document in the store.
     *
     * @param name name of the document.
     * @param content document content.
     * @return base::OptError with the error or empty if no error.
     */
    virtual base::OptError createDoc(const base::Name& name, const Doc& content) = 0;

    /**
     * @brief Read a document from the store.
     *
     * @param name name of the document.
     * @return base::RespOrError<Doc> with the document or error.
     */
    virtual base::RespOrError<Doc> readDoc(const base::Name& name) const = 0;

    /**
     * @brief Update a document in the store.
     *
     * @param name name of the document.
     * @param content document content.
     * @return base::OptError with the error or empty if no error.
     */
    virtual base::OptError updateDoc(const base::Name& name, const Doc& content) = 0;

    /**
     * @brief Upsert a document in the store.
     *
     * @param name name of the document.
     * @param content document content.
     * @return base::OptError with the error or empty if no error.
     */
    virtual base::OptError upsertDoc(const base::Name& name, const Doc& content) = 0;

    /**
     * @brief Delete a document from the store.
     *
     * @param name name of the document.
     * @return base::OptError with the error or empty if no error.
     */
    virtual base::OptError deleteDoc(const base::Name& name) = 0;

    /**
     * @brief Get collection of documents from the store.
     *
     * @param name name of the collection.
     * @return base::RespOrError<Col> with the collection or error.
     */
    virtual base::RespOrError<Col> readCol(const base::Name& name) const = 0;

    /**
     * @brief Check if a document exists in the store.
     *
     * @param name name of the document.
     * @return true if the document exists, false otherwise.
     */
    virtual bool existsDoc(const base::Name& name) const = 0;
};

} // namespace store

#endif // _STORE_ISTORE_HPP
