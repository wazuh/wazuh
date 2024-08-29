#ifndef _SCHEMF_I_SCHEMA_HPP
#define _SCHEMF_I_SCHEMA_HPP

#include <base/dotPath.hpp>
#include <base/error.hpp>
#include <base/json.hpp>
#include <schemf/type.hpp>

namespace schemf
{

/**
 * @brief Interface for a schema, allowing to query its fields.
 *
 */
class ISchema
{
public:
    virtual ~ISchema() = default;

    /**
     * @brief Get the Type of a field.
     *
     * @param name Dot-separated path to the field.
     * @return Type
     *
     * @throw std::runtime_error If the field does not exist.
     */
    virtual Type getType(const DotPath& name) const = 0;

    /**
     * @brief Get the Json Type of a field.
     *
     * @param name
     * @return json::Json::Type
     */
    virtual json::Json::Type getJsonType(const DotPath& name) const = 0;

    /**
     * @brief Query if a field is an array.
     *
     * @param name Dot-separated path to the field.
     * @return true
     * @return false
     */
    virtual bool isArray(const DotPath& name) const = 0;

    /**
     * @brief Check if a field exists.
     *
     * @param name Dot-separated path to the field.
     * @return true
     * @return false
     */
    virtual bool hasField(const DotPath& name) const = 0;
};
} // namespace schemf

#endif // _SCHEMF_I_SCHEMA_HPP
