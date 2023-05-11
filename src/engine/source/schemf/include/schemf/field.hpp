#ifndef _SCHEMF_FIELD_HPP
#define _SCHEMF_FIELD_HPP

#include <map>
#include <stack>
#include <string>

#include <json/json.hpp>

namespace schemf
{
/**
 * @brief Holds metadata about a field in a schema.
 *
 */
class Field
{
private:
    using JType = json::Json::Type;

    JType m_type;                              ///< The type of the field.
    std::map<std::string, Field> m_properties; ///< The properties of the field.
    JType m_itemsType;                         ///< The type of the items in the field.

public:
    /**
     * @brief Input parameters for constructing a Field.
     *
     * @note This is a struct instead of a class to allow for aggregate initialization.
     *
     * @param type The type of the field.
     * @param itemsType The type of the items in the field.
     * @param properties The properties of the field.
     */
    struct Parameters
    {
        JType type = JType::Null;
        JType itemsType = JType::Null;
        std::map<std::string, Field> properties = {};

        friend std::ostream& operator<<(std::ostream& os, const Parameters& parameters)
        {
            os << "FieldParameters("
               << "Type:" << parameters.type << ", ItemsType:" << parameters.itemsType
               << ", Properties:" << parameters.properties.size() << ")";

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

    Field() = default;
    ~Field() = default;
    Field(const Field&) = default;
    Field(Field&&) = default;
    Field& operator=(const Field&) = default;
    Field& operator=(Field&&) = default;

    friend bool operator==(const Field& lhs, const Field& rhs)
    {
        return lhs.m_type == rhs.m_type && lhs.m_properties == rhs.m_properties && lhs.m_itemsType == rhs.m_itemsType;
    }
    friend bool operator!=(const Field& lhs, const Field& rhs) { return !(lhs == rhs); }
    friend std::ostream& operator<<(std::ostream& os, const Field& field)
    {
        os << "Field(Type:" << field.m_type;
        if (field.m_type == JType::Array)
        {
            os << ", ItemsType:" << field.m_itemsType;
        }
        if (field.m_type == JType::Object || field.m_itemsType == JType::Object)
        {
            os << ", Properties:" << field.m_properties.size();
        }
        os << ")";
        return os;
    }

    /**
     * @brief Get the type of the field.
     *
     * @return json::Json::Type
     */
    json::Json::Type type() const;

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
     * @brief Get the type of the items in the field.
     *
     * @return json::Json::Type
     *
     * @throw std::runtime_error If the field is not an array.
     */
    json::Json::Type itemsType() const;

    /**
     * @brief Add a property to the field.
     *
     * @param name
     * @param field
     *
     * @throw std::runtime_error If the field is not an object or an array of objects.
     */
    void addProperty(const std::string& name, const Field& field);

    /**
     * @brief Add a property to the field.
     *
     * @param name
     * @param parameters
     *
     * @throw std::runtime_error If the field is not an object or an array of objects.
     */
    void addProperty(const std::string& name, const Parameters& parameters) { addProperty(name, Field(parameters)); }
};
} // namespace schemf

#endif // _SCHEMF_FIELD_HPP
