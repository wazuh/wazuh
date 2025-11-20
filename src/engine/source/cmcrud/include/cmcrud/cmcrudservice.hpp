#ifndef _CMCRUD_CMCRUDSERVICE_HPP
#define _CMCRUD_CMCRUDSERVICE_HPP

#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <base/json.hpp>
#include <base/name.hpp>

#include <cmstore/icmstore.hpp>
#include <cmstore/types.hpp>

#include <cmcrud/icmcrudservice.hpp>
#include <cmcrud/icontentvalidator.hpp>

namespace cm::crud
{

class CrudService final : public ICrudService
{
public:
    CrudService(std::shared_ptr<cm::store::ICMStore> store, std::shared_ptr<IContentValidator> validator);
    ~CrudService() override = default;

    /******************************* Namespaces *******************************/
    std::vector<cm::store::NamespaceId> listNamespaces() const override;
    void createNamespace(std::string_view nsName) override;
    void deleteNamespace(std::string_view nsName) override;

    /********************************* Policy *********************************/
    void upsertPolicy(std::string_view nsName, std::string_view policyDocument) override;
    void deletePolicy(std::string_view nsName) override;

    /***************************** Generic resources **************************/
    std::vector<ResourceSummary> listResources(std::string_view nsName, cm::store::ResourceType type) const override;
    std::string getResourceByUUID(std::string_view nsName, const std::string& uuid) const override;
    void upsertResource(std::string_view nsName, cm::store::ResourceType type, std::string_view document) override;
    void deleteResourceByUUID(std::string_view nsName, const std::string& uuid) override;

private:
    std::shared_ptr<cm::store::ICMStore> m_store;
    std::shared_ptr<IContentValidator> m_validator;

    // Namespace helpers
    std::shared_ptr<cm::store::ICMStoreNSReader> getNamespaceStoreView(const cm::store::NamespaceId& nsId) const;
    std::shared_ptr<cm::store::ICMstoreNS> getNamespaceStore(const cm::store::NamespaceId& nsId) const;
};

} // namespace cm::crud

#endif // _CMCRUD_CMCRUDSERVICE_HPP