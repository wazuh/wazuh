#ifndef _BUILDER_IVALIDATOR_HPP
#define _BUILDER_IVALIDATOR_HPP

#include <optional>

#include <error.hpp>
#include <json/json.hpp>

namespace builder
{
/**
 * @brief Interface for validating Assets and Environments.
 * !important: This validate Assets as the engine sees them, not as the user, i.e., does
 * not perform schema validation
 *
 */
class IValidator
{
public:
    virtual ~IValidator() = default;

    /**
     * @brief Validate an environment.
     *
     * @param json Environment Json definition.
     * @return std::optional<base::Error> An error if the Environment is not valid.
     */
    virtual std::optional<base::Error>
    validateEnvironment(const json::Json& json) const = 0;

    // TODO: Docu
    virtual std::optional<base::Error> validateRoute(const json::Json& json) const = 0;

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
