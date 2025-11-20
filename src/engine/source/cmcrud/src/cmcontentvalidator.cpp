#include <stdexcept>

#include <cmcrud/cmcontentvalidator.hpp>

namespace cm::crud
{

ContentValidator::ContentValidator(std::shared_ptr<builder::IValidator> builderValidator)
    : m_builderValidator(std::move(builderValidator))
{
    if (!m_builderValidator)
    {
        throw std::invalid_argument("ContentValidator: builder validator pointer cannot be null");
    }
}

void ContentValidator::validateNamespace(std::string_view /*nsName*/) const
{
    // TODO: implementar reglas de validación de espacios (namespaces)
}

void ContentValidator::validatePolicy(const std::shared_ptr<cm::store::ICMStoreNSReader>& /*nsReader*/,
                                      const cm::store::dataType::Policy& /*policy*/) const
{
    // TODO: implementar validación de Policy
}

void ContentValidator::validateIntegration(const std::shared_ptr<cm::store::ICMStoreNSReader>& /*nsReader*/,
                                           const cm::store::dataType::Integration& /*integration*/) const
{
    // TODO: implementar validación de Integration
}

void ContentValidator::validateKVDB(const std::shared_ptr<cm::store::ICMStoreNSReader>& /*nsReader*/,
                                    const cm::store::dataType::KVDB& /*kvdb*/) const
{
    // TODO: implementar validación de KVDB
}

void ContentValidator::validateAsset(const std::shared_ptr<cm::store::ICMStoreNSReader>& /*nsReader*/,
                                     const base::Name& /*name*/,
                                     const json::Json& /*asset*/) const
{
    // TODO: implementar validación de assets (decoder/rule/filter/output)
}

} // namespace cm::crud
