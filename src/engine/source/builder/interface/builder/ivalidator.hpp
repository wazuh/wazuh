#ifndef _BUILDER_IVALIDATOR_HPP
#define _BUILDER_IVALIDATOR_HPP

#include <optional>

#include <error.hpp>
#include <json/json.hpp>

namespace builder
{
/**
 * @brief Interface for validating Components.
 * !important: This validates Assets as the engine sees them, not as the user, i.e., does
 * not perform schema validation
 *
 */
class IValidator
{
public:
    virtual ~IValidator() = default;

    /**
     * @brief Validate a policy.
     *
     * @param json Policy Json definition.
     * @return std::optional<base::Error> An error if the Policy is not valid.
     */
    virtual std::optional<base::Error> validatePolicy(const json::Json& json) const = 0;

    /**
     * @brief Validate an integration.
     *
     * @param json Integration Json definition.
     * @return std::optional<base::Error> An error if the Integration is not valid.
     */
    virtual std::optional<base::Error> validateIntegration(const json::Json& json) const = 0;

    /**
     * @brief Validate an Asset.
     *
     * @param json Asset Json definition.
     * @return std::optional<base::Error> An error if the Asset is not valid.
     */
    virtual std::optional<base::Error> validateAsset(const json::Json& json) const = 0;
};
} // namespace builder

#endif // _BUILDER_IVALIDATOR_HPP
