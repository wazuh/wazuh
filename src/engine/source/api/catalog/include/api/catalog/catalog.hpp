#ifndef _CATALOG_HPP
#define _CATALOG_HPP

#include <functional>
#include <memory>
#include <unordered_map>

#include <api/catalog/icatalog.hpp>
#include <builder/ivalidator.hpp>

namespace api::catalog
{

/**
 * @brief Catalog configuration.
 *
 */
struct Config
{
    /* store interface to manipulate the Asset, Environment and Schema files */
    std::shared_ptr<store::IStore> store;
    /* Validator interface to validate the Asset, Environment and Schema files */
    std::shared_ptr<builder::IValidator> validator;
    /* Name of the schema to validate assets */
    std::string assetSchema;
    /* Name of the schema to validate environments */
    std::string environmentSchema;

    /**
     * @brief Assert that the configuration is valid.
     *
     */
    void validate() const;
};

/**
 * @brief Public interface to handle the manipulation of the Assets, Environments and
 * Schemas.
 *
 * Exposes:
 *  - Asset, Environment and Schema manipulation.
 *  - Asset, Environment and Schema validation.
 *  - Type conversion of Environment and Assets.
 *  - API handlers.
 */
class Catalog : public ICatalog
{
private:
    std::shared_ptr<store::IStore> m_store;
    std::shared_ptr<builder::IValidator> m_validator;

    std::unordered_map<Resource::Format, std::function<base::RespOrError<std::string>(const json::Json&)>> m_outFormat;
    std::unordered_map<Resource::Format, std::function<base::RespOrError<json::Json>(const std::string&)>> m_inFormat;

    base::OptError validate(const Resource& item, const std::string& namespaceId, const json::Json& content) const;

    /**
     * @brief Get the Document or error from the store.
     *
     * @param resource Resource identifying the document
     * @return base::RespOrError<store::Doc> Document or error
     */
    base::RespOrError<store::Doc> getDoc(const Resource& resource) const;

    /**
     * @brief Get a collection or error from the store.
     *
     * @param resource Resource identifying the collection
     * @param namespaceId Namespace name where the collection search
     * @return base::RespOrError<store::Col>
     */
    base::RespOrError<store::Col> getCol(const Resource& resource, const std::string& namespaceId) const;

    /**
     * @brief Delete a document or error from the store.
     *
     * @param resource Resource identifying the document
     * @return base::OptError Error if the operation failed
     */
    base::OptError delDoc(const Resource& resource);

    /**
     * @brief Delete a collection or error from the store.
     *
     * @param resource Resource identifying the collection
     * @param namespaceId Namespace name where the collection is located
     * @return base::OptError Error if the operation failed
     */
    base::OptError delCol(const Resource& resource, const std::string& namespaceId);

    /**
     * @brief Checks if a resource exists in a specified namespace before performing a given operation.
     *
     * This function is designed to be a common utility for checking the existence of a resource in a namespace
     * before carrying out operations like get, put, or delete.
     *
     * @param item The resource to be checked.
     * @param namespaceId The identifier of the namespace in which to check for the resource.
     * @param operation A description of the operation to be performed (e.g., "get", "put", "delete").
     * @return An optional containing an Error if the resource check fails, or std::nullopt if the check is successful.
     */
    base::OptError checkResourceInNamespace(const api::catalog::Resource& item,
                                            const std::string& namespaceId,
                                            const std::string& operation) const;

public:
    /**
     * @brief Construct a new Catalog object
     *
     * @param config Catalog configuration
     * @throw std::runtime_error If could not initialize the catalog
     */
    Catalog(const Config& config);
    ~Catalog() override = default;

    Catalog(const Catalog&) = delete;
    Catalog& operator=(const Catalog&) = delete;

    /**
     * @copydoc api::catalog::ICatalog::postResource
     */
    base::OptError
    postResource(const Resource& collection, const std::string& namespaceStr, const std::string& content) override;

    /**
     * @copydoc api::catalog::ICatalog::putResource
     */
    base::OptError
    putResource(const Resource& item, const std::string& content, const std::string& namespaceId) override;

    /**
     * @copydoc api::catalog::ICatalog::getResource
     */
    base::RespOrError<std::string> getResource(const Resource& resource, const std::string& namespaceId) const override;

    /**
     * @copydoc api::catalog::ICatalog::deleteResource
     */
    base::OptError deleteResource(const Resource& resource, const std::string& namespaceId) override;

    /**
     * @copydoc api::catalog::ICatalog::validateResource
     */
    base::OptError
    validateResource(const Resource& item, const std::string& namespaceId, const std::string& content) const override;

    /**
     * @copydoc api::catalog::ICatalog::getNamespaces
     */
    inline std::vector<store::NamespaceId> getAllNamespaces() const override { return m_store->listNamespaces(); }
};

} // namespace api::catalog
#endif // _CATALOG_HPP
