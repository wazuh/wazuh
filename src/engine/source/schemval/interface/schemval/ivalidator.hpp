#ifndef _SCHEMVAL_IVALIDATOR_HPP
#define _SCHEMVAL_IVALIDATOR_HPP

#include <dotPath.hpp>
#include <error.hpp>
#include <hlp/hlp.hpp>
#include <json/json.hpp>
#include <schemf/type.hpp>

namespace schemval
{

using RuntimeValidator = std::function<bool(const json::Json& value)>;

/**
 * @brief Interface to validate schema fields.
 *
 */
class IValidator
{
public:
    virtual ~IValidator() = default;

    /**
     * @brief Get the Json Type for the given type.
     *
     * @param type Schema type.
     * @return json::Json::Type
     */
    virtual json::Json::Type getJsonType(schemf::Type type) const = 0;

    /**
     * @brief Check if the given field is compatible with the given type.
     *
     * @param destPath Path to the field.
     * @param type Json type.
     * @return base::OptError Error if the validation fails.
     */
    virtual base::OptError validate(const DotPath& destPath, const json::Json::Type& type) const = 0;

    /**
     * @brief Compare the given fields.
     *
     * @param destPath Destination path.
     * @param sourcePath Source path.
     * @return base::OptError Error if source path is not compatible with destination path.
     */
    virtual base::OptError validate(const DotPath& destPath, const DotPath& sourcePath) const = 0;

    /**
     * @brief Get the Runtime Validator for the given field.
     *
     * @param destPath Destination path.
     * @return base::RespOrError<RuntimeValidator> Runtime validator if the field has one, error otherwise.
     */
    virtual base::RespOrError<RuntimeValidator> getRuntimeValidator(const DotPath& destPath) const = 0;
};

} // namespace schemval

#endif // _SCHEMVAL_IVALIDATOR_HPP
