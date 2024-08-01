#ifndef _STORE_IDRIVER_H
#define _STORE_IDRIVER_H

#include <optional>
#include <variant>

#include <base/error.hpp>
#include <base/json.hpp>
#include <base/name.hpp>

namespace store
{

using Doc = json::Json; ///< Document type
using Col = std::vector<base::Name>; ///< Collection type

/**
 * @brief Store Driver Interface, defines the CRUD interface for the store documents and collections.
 *
 */
class IDriver
{
public:
    virtual ~IDriver() = default;

    /**
     * @brief Create a Document in the store.
     *
     * @param name full name of the document.
     * @param content document content.
     * @return base::OptError with the error or empty if no error.
     */
    virtual base::OptError createDoc(const base::Name& name, const Doc& content) = 0;

    /**
     * @brief Read a document from the store.
     *
     * @param name full name of the document.
     * @return base::RespOrError<Doc> with the document or error.
     */
    virtual base::RespOrError<Doc> readDoc(const base::Name& name) const = 0;

    /**
     * @brief Update a document in the store.
     *
     * @param name full name of the document.
     * @param content document content.
     * @return base::OptError with the error or empty if no error.
     */
    virtual base::OptError updateDoc(const base::Name& name, const Doc& content) = 0;

    /**
     * @brief Upsert a document in the store.
     *
     * @param name full name of the document.
     * @param content document content.
     * @return base::OptError with the error or empty if no error.
     */
    virtual base::OptError upsertDoc(const base::Name& name, const Doc& content) = 0;

    /**
     * @brief Delete a document from the store.
     *
     * @param name full name of the document.
     * @return base::OptError with the error or empty if no error.
     */
    virtual base::OptError deleteDoc(const base::Name& name) = 0;

    /**
     * @brief Read a collection from the store.
     *
     * @param name full name of the collection.
     * @return base::RespOrError<Col> with the collection or error.
     */
    virtual base::RespOrError<Col> readCol(const base::Name& name) const = 0;

    /**
     * @brief Read the root from the store.
     *
     * @param name full name of the collection.
     * @return base::RespOrError<Col> with the collection or error.
     */
    virtual base::RespOrError<Col> readRoot() const = 0;

    /**
     * @brief Delete a collection from the store.
     *
     * @param name full name of the collection.
     * @return base::OptError with the error or empty if no error.
     */
    virtual base::OptError deleteCol(const base::Name& name) = 0;

    /**
     * @brief Check if a document or collection exists in the store.
     *
     * @param name full name of the document or collection.
     * @return true if exists.
     * @return false otherwise.
     */
    virtual bool exists(const base::Name& name) const = 0;

    /**
     * @brief Check if a document exists in the store.
     *
     * @param name full name of the document.
     * @return true if exists.
     * @return false otherwise.
     */
    virtual bool existsDoc(const base::Name& name) const = 0;

    /**
     * @brief Check if a collection exists in the store.
     *
     * @param name full name of the collection.
     * @return true if exists.
     * @return false otherwise.
     */
    virtual bool existsCol(const base::Name& name) const = 0;
};
} // namespace store

#endif // _STORE_IDRIVER_H
