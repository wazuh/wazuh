#ifndef _BUILDER2_IVALIDATOR_HPP
#define _BUILDER2_IVALIDATOR_HPP

#include <base/error.hpp>
#include <base/json.hpp>

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
    virtual base::OptError validateIntegration(const json::Json& json, const std::string& namespaceId) const = 0;

    /**
     * @brief Validate an Asset.
     *
     * @param json Asset Json definition.
     * @return base::OptError An error if the Asset is not valid.
     */
    virtual base::OptError validateAsset(const json::Json& json) const = 0;

    /**
     * @brief Validate a Policy.
     *
     * @param json Policy Json definition.
     * @return base::OptError An error if the Policy is not valid.
     */
    virtual base::OptError validatePolicy(const json::Json& json) const = 0;
};

} // namespace builder

#endif // _BUILDER2_IVALIDATOR_HPP
