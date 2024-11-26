#ifndef _API_CATALOG_RESOURCE_HPP
#define _API_CATALOG_RESOURCE_HPP

#include <cstring>
#include <exception>
#include <string>

#include <fmt/format.h>

#include <base/name.hpp>
#include <eMessages/catalog.pb.h>

namespace api::catalog
{
class Resource
{

public:
    /**
     * @brief Format of the resource managed by the catalog
     */
    using Format = ::com::wazuh::api::engine::catalog::ResourceFormat;
    /**
     * @brief Type of the resource managed by the catalog
     */
    using Type = ::com::wazuh::api::engine::catalog::ResourceType;
    constexpr static auto ASSET = 0;

    /**
     * @brief Get string representation of the Format
     *
     * @param format Format to convert
     * @return constexpr auto String representation of the format
     */
    constexpr static auto formatToStr(Format format)
    {
        switch (format)
        {
            case Format::json: return "json";
            case Format::yaml: return "yaml";
            default: return "error_format";
        }
    }

    /**
     * @brief Get string representation of the Type
     *
     * @param type Type to convert
     * @return constexpr auto String representation of the type
     */
    constexpr static auto typeToStr(Type type)
    {
        switch (type)
        {
            case Type::decoder: return "decoder";
            case Type::rule: return "rule";
            case Type::filter: return "filter";
            case Type::output: return "output";
            case Type::schema: return "schema";
            case Type::collection: return "collection";
            case Type::integration: return "integration";
            default: return "unknown";
        }
    }

    /**
     * @brief Get Type from string representation
     *
     * @param type String representation of the type
     * @return Type
     */
    constexpr static auto strToType(std::string_view type)
    {
        if (type == typeToStr(Type::decoder))
        {
            return Type::decoder;
        }
        else if (type == typeToStr(Type::rule))
        {
            return Type::rule;
        }
        else if (type == typeToStr(Type::filter))
        {
            return Type::filter;
        }
        else if (type == typeToStr(Type::output))
        {
            return Type::output;
        }
        else if (type == typeToStr(Type::schema))
        {
            return Type::schema;
        }
        else if (type == typeToStr(Type::collection))
        {
            return Type::collection;
        }
        else if (type == typeToStr(Type::integration))
        {
            return Type::integration;
        }
        return Type::UNKNOWN; // For unknown types (errors)
    }

    base::Name m_name;
    Format m_format;
    Type m_type;
    bool m_validation;

    Resource()
    {
        m_name = base::Name {"ERROR_NAME"};
        m_format = Format::json;
        m_type = Type::UNKNOWN;
        m_validation = false;
    }

    Resource(const base::Name& name, Format format)
    {
        m_format = format;

        // Factory method to define a resource from a name
        // TODO: This is a temporary solution to discern the type of the resource
        // Collections are composed by a single or two part, the fisrt part is the type
        // the second part is the name
        m_name = name;
        if (name.parts().size() == 1 || name.parts().size() == 2)
        {
            m_type = Type::collection;

            // Assert name of the collection is a valid type
            if (Type::UNKNOWN == strToType(name.parts()[0].c_str()))
            {
                throw std::runtime_error(fmt::format("Invalid collection type \"{}\"", name.parts()[0]));
            }

            // Collections don't need validation
            m_validation = false;
        }
        // Asset, Environment or Schema, they are composed of three parts
        // <type><name><version>
        else if (name.parts().size() == 3)
        {
            // Get type
            m_type = strToType(name.parts()[0].c_str());

            if (Type::UNKNOWN == m_type)
            {
                throw std::runtime_error(fmt::format("Invalid type \"{}\"", name.parts()[0]));
            }
            else if (Type::collection == m_type)
            {
                throw std::runtime_error(fmt::format("Invalid collection type \"{}\"", name.parts()[0]));
            }

            // Assets and Integration needs validation
            if (Type::decoder == m_type || Type::rule == m_type || Type::filter == m_type || Type::output == m_type
                || Type::integration == m_type)
            {
                m_validation = true;
            }
            else
            {
                m_validation = false;
            }
        }
        else
        {
            throw std::runtime_error(
                fmt::format("Invalid name \"{}\" received, a name with 1, 2 or 3 parts was expected", name.fullName()));
        }
    }
};
} // namespace api::catalog

#endif // _API_CATALOG_RESOURCE_HPP
