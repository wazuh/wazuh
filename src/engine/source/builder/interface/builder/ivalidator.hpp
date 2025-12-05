#ifndef _BUILDER2_IVALIDATOR_HPP
#define _BUILDER2_IVALIDATOR_HPP

#include <base/error.hpp>
#include <base/json.hpp>
#include <cmstore/icmstore.hpp>

namespace builder
{

class IValidator
{
public:
    virtual ~IValidator() = default;

    /**
     * @brief Validate an integration.
     *
     * @param json Integration Json definition.
     * @return base::OptError An error if the Integration is not valid.
     */
    virtual base::OptError softIntegrationValidate(const std::shared_ptr<cm::store::ICMStoreNSReader>& nsReader,
                                                   const cm::store::dataType::Integration& integration) const = 0;

    /**
     * @brief Validate an Asset.
     *
     * @param json Asset Json definition.
     * @return base::OptError An error if the Asset is not valid.
     */
    virtual base::OptError validateAsset(const std::shared_ptr<cm::store::ICMStoreNSReader>& nsReader,
                                         const json::Json& assetJson) const = 0;

    /**
     * @brief Validate a Policy.
     *
     * @param json Policy Json definition.
     * @return base::OptError An error if the Policy is not valid.
     */
    virtual base::OptError softPolicyValidate(const std::shared_ptr<cm::store::ICMStoreNSReader>& nsReader,
                                              const cm::store::dataType::Policy& policy) const = 0;
};

} // namespace builder

#endif // _BUILDER2_IVALIDATOR_HPP
