#ifndef _CMCRUD_CMCRUDSERVICE_HPP
#define _CMCRUD_CMCRUDSERVICE_HPP

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <base/json.hpp>
#include <base/name.hpp>

#include <builder/ivalidator.hpp>
#include <cmstore/icmstore.hpp>
#include <cmstore/types.hpp>

#include <cmcrud/icmcrudservice.hpp>

namespace cm::crud
{

class CrudService final : public ICrudService
{
public:
    CrudService(const std::shared_ptr<cm::store::ICMStore>& store,
                const std::shared_ptr<builder::IValidator>& validator);

    ~CrudService() override = default;

    /******************************* Namespaces *******************************/
    std::vector<cm::store::NamespaceId> listNamespaces() const override;
    void createNamespace(const cm::store::NamespaceId& nsId) override;
    bool existsNamespace(const cm::store::NamespaceId& nsId) const override;
    void deleteNamespace(const cm::store::NamespaceId& nsId) override;
    void importNamespace(const cm::store::NamespaceId& nsId,
                         std::string_view jsonDocument,
                         std::string_view origin,
                         bool force) override;
    void importNamespace(const cm::store::NamespaceId& nsId,
                         const std::vector<json::Json>& kvdbs,
                         const std::vector<json::Json>& decoders,
                         const std::vector<json::Json>& integrations,
                         const json::Json& policy,
                         bool softValidation,
                         std::optional<std::string> externalPolicyHash = std::nullopt) override;

    /********************************* Policy *********************************/
    void upsertPolicy(const cm::store::NamespaceId& nsId, std::string_view policyDocument) override;
    void deletePolicy(const cm::store::NamespaceId& nsId) override;

    /***************************** Generic resources **************************/
    std::vector<ResourceSummary> listResources(const cm::store::NamespaceId& nsId,
                                               cm::store::ResourceType type) const override;
    std::string
    getResourceByUUID(const cm::store::NamespaceId& nsId, const std::string& uuid, bool asJson) const override;
    void upsertResource(const cm::store::NamespaceId& nsId,
                        cm::store::ResourceType type,
                        std::string_view document) override;
    void deleteResourceByUUID(const cm::store::NamespaceId& nsId, const std::string& uuid) override;

    // Public validate
    void validateResource(cm::store::ResourceType type, const json::Json& payload) override;

private:
    std::weak_ptr<cm::store::ICMStore> m_store;
    std::weak_ptr<builder::IValidator> m_validator;

    // Helper methods to safely access weak_ptr resources
    std::shared_ptr<cm::store::ICMStore> getStore() const;
    std::shared_ptr<builder::IValidator> getValidator() const;

    void validatePolicy(const std::shared_ptr<cm::store::ICMStoreNSReader>& nsReader,
                        const cm::store::dataType::Policy& policy) const;
    void validateIntegration(const std::shared_ptr<cm::store::ICMStoreNSReader>& nsReader,
                             const cm::store::dataType::Integration& integration) const;
    void validateAsset(const std::shared_ptr<cm::store::ICMStoreNSReader>& nsReader, const json::Json& asset) const;

    // Namespace helpers
    std::shared_ptr<cm::store::ICMStoreNSReader> getNamespaceStoreView(const cm::store::NamespaceId& nsId) const;
    std::shared_ptr<cm::store::ICMstoreNS> getNamespaceStore(const cm::store::NamespaceId& nsId) const;
};

} // namespace cm::crud

#endif // _CMCRUD_CMCRUDSERVICE_HPP
