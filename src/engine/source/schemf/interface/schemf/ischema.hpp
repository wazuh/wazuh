#ifndef _SCHEMF_I_SCHEMA_HPP
#define _SCHEMF_I_SCHEMA_HPP

#include <json/json.hpp>

#include "dotPath.hpp"

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
};
} // namespace schemf

#endif // _SCHEMF_I_SCHEMA_HPP
