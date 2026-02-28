#ifndef _SCHEMF_FIELD_HPP
#define _SCHEMF_FIELD_HPP

#include <map>
#include <optional>
#include <string>

#include <base/json.hpp>
#include <schemf/type.hpp>

#include <base/error.hpp>

namespace schemf
{

/**
 * @brief Holds metadata about a field in a schema.
 *
 */
class Field
{
private:
    Type m_type;                               ///< The type of the field.
    std::map<std::string, Field> m_properties; ///< The properties of the field.

public:
    /**
     * @brief Input parameters for constructing a Field.
     *
     * @note This is a struct instead of a class to allow for aggregate initialization.
     *
     * @param type The type of the field.
     * @param properties The properties of the field.
     */
    struct Parameters
    {
        Type type = Type::ERROR;
        std::map<std::string, Field> properties = {};

    /**
     * @brief Stream insertion operator for Field::Parameters.
     *
     * @param os Output stream.
     * @param parameters The parameters to print.
     * @return std::ostream& The output stream.
     */
    friend std::ostream& operator<<(std::ostream& os, const Parameters& parameters)
        {
            os << "FieldParameters(" << "Type:" << typeToStr(parameters.type) << std::boolalpha
                << "Properties:" << parameters.properties.size() << ")";

            return os;
        }
    };

    /**
     * @brief Construct a new Field object.
     *
     * @param parameters The parameters to construct the field with.
     *
     * @throw std::runtime_error If the parameters are invalid.
     */
    explicit Field(const Parameters& parameters);

    /** @brief Default constructor, creates a field with Type::ERROR. */
    Field()
        : m_type(Type::ERROR)
    {
    }
    ~Field() = default;
    Field(const Field&) = default;
    Field(Field&&) = default;
    Field& operator=(const Field&) = default;
    Field& operator=(Field&&) = default;

    /**
     * @brief Equality comparison operator.
     *
     * @param lhs Left-hand side Field.
     * @param rhs Right-hand side Field.
     * @return true if type and properties are equal.
     */
    friend bool operator==(const Field& lhs, const Field& rhs)
    {
        return lhs.m_type == rhs.m_type && lhs.m_properties == rhs.m_properties;
    }
    /** @brief Inequality comparison operator. */
    friend bool operator!=(const Field& lhs, const Field& rhs) { return !(lhs == rhs); }
    /**
     * @brief Stream insertion operator.
     *
     * @param os Output stream.
     * @param field The field to print.
     * @return std::ostream& The output stream.
     */
    friend std::ostream& operator<<(std::ostream& os, const Field& field)
    {
        os << "Field(Type:" << typeToStr(field.m_type) << std::boolalpha
            << ", Properties:" << field.m_properties.size() << ")";

        return os;
    }

    /**
     * @brief Get the type of the field.
     *
     * @return Type
     */
    inline Type type() const { return m_type; }

    /**
     * @brief Get the properties of the field.
     *
     * @return const std::map<std::string, Field>&
     *
     * @throw std::runtime_error If the field is not an object or an array of objects.
     */
    const std::map<std::string, Field>& properties() const;

    /**
     * @brief Get the properties of the field.
     *
     * @return std::map<std::string, Field>&
     *
     * @throw std::runtime_error If the field is not an object or an array of objects.
     */
    std::map<std::string, Field>& properties();

    /**
     * @brief Add a property to the field.
     *
     * @param name Name of the property.
     * @param field The Field to add.
     *
     * @throw std::runtime_error If the field is not an object or an array of objects.
     */
    void addProperty(const std::string& name, const Field& field);

    /**
     * @brief Add a property to the field from parameters.
     *
     * @param name Name of the property.
     * @param parameters Parameters to construct the field with.
     *
     * @throw std::runtime_error If the field is not an object or an array of objects.
     */
    void addProperty(const std::string& name, const Parameters& parameters) { addProperty(name, Field(parameters)); }
};
} // namespace schemf

#endif // _SCHEMF_FIELD_HPP
