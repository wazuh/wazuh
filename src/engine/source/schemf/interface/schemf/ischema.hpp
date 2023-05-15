#ifndef _SCHEMF_I_SCHEMA_HPP
#define _SCHEMF_I_SCHEMA_HPP

#include <optional>

#include <json/json.hpp>

#include "dotPath.hpp"
#include "error.hpp"

namespace schemf
{
/**
 * @brief Interface for a schema, allowing to query its fields.
 *
 */
class ISchema
{
public:
    using RuntimeValidator = std::function<std::optional<base::Error>(const json::Json&)>;

    virtual ~ISchema() = default;
    /**
     * @brief Get the Type of a field.
     *
     * @param name Dot-separated path to the field.
     * @return json::Json::Type
     *
     * @throw std::runtime_error If the field does not exist.
     */
    virtual json::Json::Type getType(const DotPath& name) const = 0;

    /**
     * @brief Check if a field exists.
     *
     * @param name Dot-separated path to the field.
     * @return true
     * @return false
     */
    virtual bool hasField(const DotPath& name) const = 0;

    /**
     * @brief Validate that target field and value are type-compatible.
     *
     * @param target Dot-separated path to the field.
     * @param value Value to validate.
     * @return std::optional<base::Error> If they are not compatible, an error is returned.
     */
    virtual std::optional<base::Error> validate(const DotPath& target, const json::Json& value) const = 0;

    /**
     * @brief Validate that target field and reference field are type-compatible.
     *
     * @param target Dot-separated path to the field.
     * @param reference Dot-separated path to the field.
     * @return std::optional<base::Error> If they are not compatible, an error is returned.
     */
    virtual std::optional<base::Error> validate(const DotPath& target, const DotPath& reference) const = 0;

    /**
     * @brief Get a runtime validator function for the target field.
     *
     * @param target Dot-separated path to the field.
     * @return RuntimeValidator A function that takes a json::Json and returns an error if the value is incompatible.
     */
    virtual RuntimeValidator getRuntimeValidator(const DotPath& target) const = 0;
};
} // namespace schemf

#endif // _SCHEMF_I_SCHEMA_HPP
