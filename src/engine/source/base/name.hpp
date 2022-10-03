#ifndef _BASE_NAME_HPP
#define _BASE_NAME_HPP

#include <string>

#include <fmt/format.h>

#include "utils/stringUtils.hpp"

namespace base
{

/**
 * @brief Name of a store resource.
 *
 * It's composed of type, name and version. Uniquely identifies a resource.
 * Details of the resource path and storage are handled by the store driver.
 *
 * Name can be constructed from a string in the form:
 * <type>SEPARATOR<name>SEPARATOR<version> Where SEPARATOR is the separator character,
 * currently '.'
 *
 * @note The name is not a path, it's a name.
 */
class Name
{
private:
    void copy(const Name& other)
    {
        m_type = other.m_type;
        m_name = other.m_name;
        m_version = other.m_version;
    }

public:
    constexpr static auto SEPARATOR_S = ".";
    constexpr static auto SEPARATOR_C = '.';

    std::string m_type;
    std::string m_name;
    std::string m_version;

    Name() = default;

    /**
     * @brief Construct a new Name object
     *
     * @param type Type string
     * @param name Name string
     * @param version Version string
     *
     * @throw std::runtime_error if any of the strings is empty
     */
    Name(const std::string& type, const std::string& name, const std::string& version)
        : m_type(type)
        , m_name(name)
        , m_version(version)
    {
        if (m_type.empty() || m_name.empty() || m_version.empty())
        {
            throw std::runtime_error("[Name] Name parts cannot be empty");
        }
    }

    /**
     * @brief Construct a new Name object
     *
     * @param fullName Name string in the form <type>SEPARATOR<name>SEPARATOR<version>
     *
     * @throw std::runtime_error if the string does not have the correct format
     */
    Name(const std::string& fullName)
    {
        auto parts = utils::string::split(fullName, SEPARATOR_C);
        if (parts.size() != 3)
        {
            throw std::runtime_error(fmt::format("[Name] Invalid name [{}]", fullName));
        }

        for (const auto& part : parts)
        {
            if (part.empty())
            {
                throw std::runtime_error(
                    fmt::format("[Name] Invalid name [{}]", fullName));
            }
        }

        m_type = parts[0];
        m_name = parts[1];
        m_version = parts[2];
    }

    /**
     * @brief Construct a new Name object
     *
     * @param fullName Name c_string in the form <type>SEPARATOR<name>SEPARATOR<version>
     *
     * @throw std::runtime_error if the string does not have the correct format
     */
    Name(const char* fullName)
        : Name(std::string(fullName))
    {
    }

    /**
     * @brief Construct a new Name object
     *
     * @param other Name to copy
     */
    Name(const Name& other) { copy(other); }

    /**
     * @brief Copy assignment operator
     *
     * @param other Name to copy
     * @return Name& self
     */
    Name& operator=(const Name& other)
    {
        if (this != &other)
        {
            copy(other);
        }

        return *this;
    }

    /**
     * @brief Equality comparison operator
     *
     * @param other Name to compare
     * @return true
     * @return false
     */
    bool operator==(const Name& other) const
    {
        return m_type == other.m_type && m_name == other.m_name
               && m_version == other.m_version;
    }

    /**
     * @brief Inequality comparison operator
     *
     * @param other Name to compare
     * @return true
     * @return false
     */
    bool operator!=(const Name& other) const { return !(*this == other); }

    /**
     * @brief Get the full name string
     *
     * @return std::string Full name string in the form
     * <type>SEPARATOR<name>SEPARATOR<version>
     */
    std::string fullName() const
    {
        return m_type + SEPARATOR_S + m_name + SEPARATOR_S + m_version;
    }
};

} // namespace base

#endif // _BASE_NAME_HPP
