#include <sstream>

#include "field.hpp"

#include <fmt/format.h>

namespace schemf
{
Field::Field(const Parameters& parameters)
{
    if (parameters.type == Type::ERROR)
    {
        throw std::runtime_error("Unknown type");
    }

    if (!hasProperties(parameters.type) && !parameters.properties.empty())
    {
        throw std::runtime_error(
            fmt::format("Cannot add properties to non-object field '{}'", typeToStr(parameters.type)));
    }

    m_type = parameters.type;
    m_properties = parameters.properties;
    m_isArray = parameters.isArray;
}

const std::map<std::string, Field>& Field::properties() const
{
    if (!hasProperties(m_type))
    {
        throw std::runtime_error(fmt::format("Cannot get properties of non-object field '{}'", typeToStr(m_type)));
    }
    return m_properties;
}

std::map<std::string, Field>& Field::properties()
{
    if (!hasProperties(m_type))
    {
        throw std::runtime_error(fmt::format("Cannot get properties of non-object field '{}'", typeToStr(m_type)));
    }
    return m_properties;
}

void Field::addProperty(const std::string& name, const Field& field)
{
    if (!hasProperties(m_type))
    {
        throw std::runtime_error(fmt::format("Cannot add properties to non-object field '{}'", typeToStr(m_type)));
    }

    if (m_properties.find(name) != m_properties.end())
    {
        throw std::runtime_error("Property already exists");
    }

    m_properties.emplace(name, field);
}

} // namespace schemf
