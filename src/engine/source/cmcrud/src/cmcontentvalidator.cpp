#include <stdexcept>

#include <fmt/format.h>

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

void ContentValidator::validatePolicy(const std::shared_ptr<cm::store::ICMStoreNSReader>& nsReader,
                                      const cm::store::dataType::Policy& policy) const
{
    base::OptError err = m_builderValidator->softPolicyValidate(nsReader, policy);
    if (err.has_value())
    {
        const auto& e = base::getError(err); // o simplemente err->message
        throw std::runtime_error(fmt::format(
            "Policy validation failed in namespace '{}': {}", nsReader->getNamespaceId().toStr(), e.message));
    }
}

void ContentValidator::validateIntegration(const std::shared_ptr<cm::store::ICMStoreNSReader>& nsReader,
                                           const cm::store::dataType::Integration& integration) const
{
    base::OptError err = m_builderValidator->softIntegrationValidate(nsReader, integration);
    if (err.has_value())
    {
        const auto& e = base::getError(err);
        throw std::runtime_error(fmt::format("Integration validation failed for '{}' in namespace '{}': {}",
                                             integration.getName(),
                                             nsReader->getNamespaceId().toStr(),
                                             e.message));
    }
}

void ContentValidator::validateKVDB(const std::shared_ptr<cm::store::ICMStoreNSReader>& /*nsReader*/,
                                    const cm::store::dataType::KVDB& /*kvdb*/) const
{
    // Currently, no validation is performed for KVDBs.
}

void ContentValidator::validateAsset(const std::shared_ptr<cm::store::ICMStoreNSReader>& nsReader,
                                     const json::Json& asset) const
{
    auto err = m_builderValidator->validateAsset(nsReader, asset);
    if (err.has_value())
    {
        const auto& e = base::getError(err);
        throw std::runtime_error(fmt::format(
            "Asset validation failed in namespace '{}': {}", nsReader->getNamespaceId().toStr(), e.message));
    }
}

} // namespace cm::crud
