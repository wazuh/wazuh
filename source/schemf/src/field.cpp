#include <sstream>

#include "field.hpp"

namespace schemf
{
Field::Field(const Parameters& parameters)
{
    if (parameters.type == JType::Null)
    {
        throw std::runtime_error("Cannot create field with null type");
    }

    if (parameters.type == JType::Array && parameters.itemsType == JType::Null)
    {
        throw std::runtime_error("Cannot create array field without items type");
    }

    if (parameters.type != JType::Object && parameters.itemsType != JType::Object && !parameters.properties.empty())
    {
        throw std::runtime_error("Cannot add properties to non-object field or array field of non-objects");
    }

    if (parameters.type != JType::Array && parameters.itemsType != JType::Null)
    {
        throw std::runtime_error("Cannot set items type for non-array field");
    }

    m_type = parameters.type;
    m_properties = parameters.properties;
    m_itemsType = parameters.itemsType;
}

Field::Field(const json::Json& value)
{
    if (value.type() == json::Json::Type::Null)
    {
        throw std::runtime_error("Cannot create field with null type");
    }

    m_type = value.type();
    m_itemsType = JType::Null;
    m_properties = {};

    if (m_type == JType::Object)
    {
        auto properties = value.getObject().value();
        for (const auto& [name, value] : properties)
        {
            m_properties[name] = Field(value);
        }
    }
    else if (m_type == JType::Array)
    {
        if (value.size() < 1)
        {
            throw std::runtime_error("Cannot create array field without items type");
        }

        m_itemsType = value.getArray().value()[0].type();
        if (m_itemsType == JType::Object)
        {
            auto properties = value.getArray().value()[0].getObject().value();
            for (const auto& [name, value] : properties)
            {
                m_properties[name] = Field(value);
            }
        }
    }
}

json::Json::Type Field::type() const
{
    return m_type;
}

const std::map<std::string, Field>& Field::properties() const
{
    if (m_type != JType::Object && m_itemsType != JType::Object)
    {
        throw std::runtime_error("Cannot get properties of non-object field or array of non-object items");
    }
    return m_properties;
}

std::map<std::string, Field>& Field::properties()
{
    if (m_type != JType::Object && m_itemsType != JType::Object)
    {
        throw std::runtime_error("Cannot get properties of non-object field or array of non-object items");
    }
    return m_properties;
}

void Field::addProperty(const std::string& name, const Field& field)
{
    if (m_type != JType::Object && m_itemsType != JType::Object)
    {
        throw std::runtime_error("Cannot get properties of non-object field or array of non-object items");
    }

    if (m_properties.find(name) != m_properties.end())
    {
        throw std::runtime_error("Property already exists");
    }

    m_properties[name] = field;
}

json::Json::Type Field::itemsType() const
{
    if (m_type != JType::Array)
    {
        throw std::runtime_error("Cannot get items type of non-array field");
    }
    return m_itemsType;
}

} // namespace schemf
