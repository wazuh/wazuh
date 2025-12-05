#ifndef _CM_CRUD_CONTENT_VALIDATOR_HPP
#define _CM_CRUD_CONTENT_VALIDATOR_HPP

#include <memory>
#include <string_view>

#include <builder/ivalidator.hpp>

#include <cmcrud/icontentvalidator.hpp>

namespace cm::crud
{

class ContentValidator final : public IContentValidator
{
public:
    explicit ContentValidator(std::shared_ptr<builder::IValidator> builderValidator);
    ~ContentValidator() override = default;

    void validatePolicy(const std::shared_ptr<cm::store::ICMStoreNSReader>& nsReader,
                        const cm::store::dataType::Policy& policy) const override;

    void validateIntegration(const std::shared_ptr<cm::store::ICMStoreNSReader>& nsReader,
                             const cm::store::dataType::Integration& integration) const override;

    void validateKVDB(const std::shared_ptr<cm::store::ICMStoreNSReader>& nsReader,
                      const cm::store::dataType::KVDB& kvdb) const override;

    void validateAsset(const std::shared_ptr<cm::store::ICMStoreNSReader>& nsReader,
                       const json::Json& asset) const override;

private:
    std::shared_ptr<builder::IValidator> m_builderValidator;
};

} // namespace cm::crud

#endif // _CM_CRUD_CONTENT_VALIDATOR_HPP
