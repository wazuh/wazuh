#ifndef _SCHEMF_SCHEMA_HPP
#define _SCHEMF_SCHEMA_HPP

#include <map>

#include <schemf/ischema.hpp>

#include "field.hpp"

namespace schemf
{
/**
 * @brief A schema, which holds a graph of fields.
 *
 */
class Schema final : public ISchema
{
private:
    std::map<std::string, Field> m_fields; ///< First level fields of the schema.

    const Field& get(const DotPath& name) const;

public:
    /**
     * @brief Add a field to the schema. Parent fields will be created if they do not exist.
     *
     * @param name Dot-separated path to the field.
     * @param field The field to add.
     *
     * @throw std::runtime_error If the field cannot be added.
     */
    void addField(const DotPath& name, const Field& field);

    /**
     * @brief Add a field to the schema. Parent fields will be created if they do not exist.
     *
     * @param name Dot-separated path to the field.
     * @param field Parameters to construct the field with.
     *
     * @throw std::runtime_error If the field cannot be added.
     */
    void addField(const DotPath& name, const Field::Parameters& field) { addField(name, Field(field)); }

    /**
     * @brief Remove a field from the schema. If the field has children, they will be removed as well.
     *
     * @param name Dot-separated path to the field.
     *
     * @throw std::runtime_error If the field cannot be removed.
     */
    void removeField(const DotPath& name);

    /**
     * @copydoc ISchema::getType
     */
    json::Json::Type getType(const DotPath& name) const override;

    /**
     * @copydoc ISchema::hasField
     */
    bool hasField(const DotPath& name) const override;
};
} // namespace schemf

#endif // _SCHEMF_SCHEMA_HPP
