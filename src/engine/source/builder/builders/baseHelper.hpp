#ifndef _BASE_HELPER_H
#define _BASE_HELPER_H

#include <any>
#include <string>
#include <tuple>
#include <vector>

#include <defs/idefinitions.hpp>

namespace helper::base
{

/**
 * @brief Struct to handle that parameters may be a value or a reference.
 *
 */
struct Parameter
{
    enum class Type
    {
        REFERENCE,
        VALUE
    };

    Type m_type;
    std::string m_value;

    friend std::ostream& operator<<(std::ostream& os, const Parameter& parameter)
    {
        os << parameter.m_value;
        return os;
    }

    friend bool operator==(const Parameter& lhs, const Parameter& rhs)
    {
        return lhs.m_type == rhs.m_type && lhs.m_value == rhs.m_value;
    }
};

/**
 * @brief Transforms a vector of strings into a vector of Parameters.
 * If the string is a reference, it will be transformed into a Parameter with
 * Type::REFERENCE and the reference will be transformed into a JSON pointer path.
 * If the string is a definition, it will be transformed into a Parameter with
 * Type::VALUE and the value will be the string or string representation of the definition value.
 * If the string is a value, it will be transformed into a Parameter with Type::VALUE.
 *
 * @param name name of the helper
 * @param parameters vector of strings
 * @param definitions definitions to check if a reference is a definition
 * @param checkDefinitionType check if the definition value is string or number
 * @return std::vector<Parameter>
 *
 * @throws std::runtime_error if a reference parameter cannot be transformed into a JSON
 * pointer path.
 */
std::vector<Parameter> processParameters(const std::string& name,
                                         const std::vector<std::string>& parameters,
                                         std::shared_ptr<defs::IDefinitions> definitions,
                                         const bool checkDefinitionType = true);

/**
 * @brief Check that the number of parameters is correct and throw otherwise.
 *
 * @param name name of the helper
 * @param parameters
 * @param size
 *
 * @throws std::runtime_error if the number of parameters is not correct.
 */
void checkParametersSize(const std::string& name, const std::vector<Parameter>& parameters, size_t size);

/**
 * @brief Check that the number of parameters is equal or bigger than
 * minimum and throw otherwise.
 *
 * @param name name of the helper
 * @param parameters vector of parameters to check
 * @param size minimum size of parameters
 *
 * @throws std::runtime_error if the number of parameters is not correct.
 */
void checkParametersMinSize(const std::string& name, const std::vector<Parameter>& parameters, const size_t minSize);
/**
 * @brief Check that the paremeter is of Parameter::Type and throw otherwise.
 *
 * @param name name of the helper
 * @param parameter
 * @param type
 *
 * @throws std::runtime_error if the parameter is not of the expected type.
 */
void checkParameterType(const std::string& name, const Parameter& parameter, Parameter::Type type);

/**
 * @brief Format the name to be used in Tracers.
 * Format: "helper.<name>[<targetField>/<parameters>]"
 *
 * @param targetField
 * @param name
 * @param parameters
 * @return std::string
 */
std::string
formatHelperName(const std::string& targetField, const std::string& name, const std::vector<Parameter>& parameters);

} // namespace helper::base

#endif // _BASE_HELPER_H
