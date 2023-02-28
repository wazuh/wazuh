#ifndef _CATALOG_RESOURCE_HPP
#define _CATALOG_RESOURCE_HPP

#include <cstring>
#include <exception>
#include <string>

#include <fmt/format.h>

#include <eMessages/catalog.pb.h>
#include <name.hpp>

namespace api::catalog
{
class Resource
{

public:
    using Format = ::com::wazuh::api::engine::catalog::ResourceFormat;
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
            case Format::JSON: return "json";
            case Format::YAML: return "yaml";
            default: return "error_format";
        }
    }

    /**
     * @brief Type of the resources handled by the catalog
     *
     */
    enum class Type
    {
        DECODER,
        RULE,
        FILTER,
        OUTPUT,
        ENVIRONMENT,
        SCHEMA,
        COLLECTION,
        ERROR_TYPE
    };

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
            case Type::DECODER: return "decoder";
            case Type::RULE: return "rule";
            case Type::FILTER: return "filter";
            case Type::OUTPUT: return "output";
            case Type::ENVIRONMENT: return "environment";
            case Type::SCHEMA: return "schema";
            case Type::COLLECTION: return "collection";
            default: return "error_type";
        }
    }

    /**
     * @brief Get Type from string representation
     *
     * @param type String representation of the type
     * @return Type
     */
    constexpr static auto strToType(const char* type)
    {
        if (std::strcmp(type, typeToStr(Type::DECODER)) == 0)
        {
            return Type::DECODER;
        }
        else if (std::strcmp(type, typeToStr(Type::RULE)) == 0)
        {
            return Type::RULE;
        }
        else if (std::strcmp(type, typeToStr(Type::FILTER)) == 0)
        {
            return Type::FILTER;
        }
        else if (std::strcmp(type, typeToStr(Type::OUTPUT)) == 0)
        {
            return Type::OUTPUT;
        }
        else if (std::strcmp(type, typeToStr(Type::ENVIRONMENT)) == 0)
        {
            return Type::ENVIRONMENT;
        }
        else if (std::strcmp(type, typeToStr(Type::SCHEMA)) == 0)
        {
            return Type::SCHEMA;
        }
        else if (std::strcmp(type, typeToStr(Type::COLLECTION)) == 0)
        {
            return Type::COLLECTION;
        }
        else
        {
            return Type::ERROR_TYPE;
        }
    }

    base::Name m_name;
    Format m_format;
    Type m_type;
    bool m_validation;

    Resource()
    {
        m_name = base::Name {"ERROR_NAME"};
        m_format = Format::ERROR_FORMAT;
        m_type = Type::ERROR_TYPE;
        m_validation = false;
    }

    Resource(const base::Name& name, Format format)
    {
        // Assert we don't have an error enum
        if (Format::ERROR_FORMAT == format)
        {
            throw std::runtime_error(
                fmt::format("Format of \"{}\" not supported", name.fullName()));
        }
        m_format = format;

        // Factory method to define a resource from a name
        // TODO: This is a temporary solution to discern the type of the resource
        // Collections are composed by a single or two part, the fisrt part is the type
        // the second part is the name
        m_name = name;
        if (name.parts().size() == 1 || name.parts().size() == 2)
        {
            m_type = Type::COLLECTION;

            // Assert name of the collection is a valid type
            if (Type::ERROR_TYPE == strToType(name.parts()[0].c_str()))
            {
                throw std::runtime_error(
                    fmt::format("Invalid collection type \"{}\"", name.parts()[0]));
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

            if (Type::ERROR_TYPE == m_type)
            {
                throw std::runtime_error(
                    fmt::format("Invalid type \"{}\"", name.parts()[0]));
            }
            else if (Type::COLLECTION == m_type)
            {
                throw std::runtime_error(
                    fmt::format("Invalid collection type \"{}\"", name.parts()[0]));
            }

            // Assets and Environments needs validation
            if (Type::ENVIRONMENT == m_type || Type::DECODER == m_type || Type::RULE == m_type
                || Type::FILTER == m_type || Type::OUTPUT == m_type)
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
            throw std::runtime_error(fmt::format(
                "Invalid name \"{}\" received, a name with 1, 2 or 3 parts was expected",
                name.fullName()));
        }
    }
};
} // namespace api::catalog

#endif // _WAZUH_RESOURCE_H_
