#ifndef _SCHEMVAL_IVALIDATOR_HPP
#define _SCHEMVAL_IVALIDATOR_HPP

#include <dotPath.hpp>
#include <error.hpp>
#include <hlp/hlp.hpp>
#include <json/json.hpp>
#include <schemf/type.hpp>
#include <schemval/validationToken.hpp>

namespace schemval
{

using RuntimeValidator = std::function<bool(const json::Json& value)>;
using BuildtimeValidator = std::function<bool(const ValidationToken& token)>;

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
     * @brief Validate the given field with the given token.
     *
     * @param destPath Destination path.
     * @param token Token to validate.
     * @return base::OptError Error if the token is not compatible with the field.
     */
    virtual base::OptError validate(const DotPath& destPath, const ValidationToken& token) const = 0;

    /**
     * @brief Validate if the given array field item is compatible with the given token.
     *
     * @param destPath Destination path.
     * @param token Token to validate.
     * @return base::OptError Error if the token is not compatible with the field array item.
     */
    virtual base::OptError validateArray(const DotPath& destPath, const ValidationToken& token) const = 0;

    /**
     * @brief Get the Runtime Validator for the given field.
     *
     * @param destPath Destination path.
     * @param ignoreArray If set to true, the validator will validate the field as if it was not an array.
     * @return base::RespOrError<RuntimeValidator> Runtime validator if the field has one, error otherwise.
     */
    virtual base::RespOrError<RuntimeValidator> getRuntimeValidator(const DotPath& destPath,
                                                                    bool ignoreArray = false) const = 0;

    virtual ValidationToken createToken(json::Json::Type type) const = 0;
    virtual ValidationToken createToken(schemf::Type type) const = 0;
    virtual ValidationToken createToken(const json::Json& value) const = 0;
    virtual ValidationToken createToken(const DotPath& path) const = 0;
    virtual ValidationToken createToken() const = 0;
};

} // namespace schemval

#endif // _SCHEMVAL_IVALIDATOR_HPP
