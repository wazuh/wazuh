#ifndef _SCHEMF_SCHEMA_HPP
#define _SCHEMF_SCHEMA_HPP

#include <experimental/propagate_const>
#include <map>
#include <string>

#include <schemf/field.hpp>
#include <schemf/ischema.hpp>
#include <schemf/ivalidator.hpp>

namespace schemf
{
/**
 * @brief A schema, which holds a graph of fields.
 *
 */
class Schema final : public IValidator
{
private:
    std::map<std::string, Field> m_fields; ///< First level fields of the schema.
    class Validator;
    std::experimental::propagate_const<std::unique_ptr<Validator>> m_validator;

    Field get(const DotPath& name) const;

    /**
     * @brief Convert a field JSON entry to a Schema Field object.
     *
     * @param name Entry field's name.
     * @param entry JSON entry with the field description.
     * @return Field The Schema Field object.
     *
     * @throw std::runtime_error If the entry is invalid.
     */
    Field entryToField(const std::string& name, const json::Json& entry) const;

public:
    Schema();
    ~Schema();

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
    inline Type getType(const DotPath& name) const override { return get(name).type(); }

    /**
     * @copydoc ISchema::getJsonType
     */
    inline json::Json::Type getJsonType(const DotPath& name) const override { return typeToJType(get(name).type()); }

    /**
     * @copydoc ISchema::hasField
     */
    bool hasField(const DotPath& name) const override;

    /**
     * @copydoc ISchema::isArray
     */
    inline bool isArray(const DotPath& name) const override { return get(name).isArray(); }

    /**
     * @brief Load a schema from a JSON object, adding each field to the schema.
     *
     * @param json The JSON object schema.
     */
    void load(const json::Json& json);

    /**
     * @copydoc IValidator::validate
     */
    base::RespOrError<ValidationResult> validate(const DotPath& name, const ValidationToken& token) const override;
};
} // namespace schemf

#endif // _SCHEMF_SCHEMA_HPP
