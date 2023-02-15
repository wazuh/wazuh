#ifndef _BASE_NAME_HPP
#define _BASE_NAME_HPP

#include <initializer_list>
#include <iostream>
#include <numeric>
#include <sstream>
#include <string>
#include <vector>

#include <fmt/format.h>
#include <logging/logging.hpp>

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
 * <part>[SEPARATOR<part>...] Where SEPARATOR is the separator character,
 * currently '/'
 *
 * @note The name is not a path, it's a name.
 */
class Name
{
public:
    constexpr static auto SEPARATOR_S = "/";
    constexpr static auto SEPARATOR_C = '/';
    constexpr static auto MAX_PARTS = 10;

private:
    std::vector<std::string> m_parts;

    void assertSize(size_t size) const
    {
        if (0 == size)
        {
            throw std::runtime_error(fmt::format("Name cannot be empty"));
        }
        if (MAX_PARTS < size)
        {
            WAZUH_LOG_DEBUG(
                "Engine base name: \"{}\" method: Name \"{}\".", __func__, fullName());

            throw std::runtime_error(fmt::format("Name size must have {} parts at most "
                                                 "at most, but the one inserted has {}",
                                                 MAX_PARTS,
                                                 size));
        }
    }

    void copy(const Name& other) { m_parts = other.m_parts; }
    void copyMove(Name&& other) noexcept { m_parts = std::move(other.m_parts); }

public:
    Name() = default;

    /**
     * @brief Construct a new Name object
     *
     * @tparam Parts Parameter pack of string types
     * @param parts Parts of the name
     */
    Name(const std::vector<std::string>& parts)
    {
        assertSize(parts.size());
        m_parts = parts;
    }

    /**
     * @brief Construct a new Name object
     *
     * @param fullName Name string in the form <part>SEPARATOR<part>...
     * @throw std::runtime_error if the string does not have the correct format
     */
    Name(const std::string& fullName)
    {
        m_parts = base::utils::string::split(fullName, SEPARATOR_C);
        assertSize(m_parts.size());
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
     * @brief Construct a new Name object
     *
     * @param other Name to move
     */
    Name(Name&& other) noexcept { copyMove(std::move(other)); }

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
     * @brief Move assignment operator
     *
     * @param other Name to move
     * @return Name& self
     */
    Name& operator=(Name&& other) noexcept
    {
        copyMove(std::move(other));

        return *this;
    }

    /**
     * @brief Equality comparison operator
     *
     * @param other Name to compare
     * @return true
     * @return false
     */
    bool operator==(const Name& other) const { return m_parts == other.m_parts; }

    /**
     * @brief Inequality comparison operator
     *
     * @param other Name to compare
     * @return true
     * @return false
     */
    bool operator!=(const Name& other) const { return !(*this == other); }

    friend std::ostream& operator<<(std::ostream& os, const Name& name)
    {
        os << std::accumulate(
            name.m_parts.begin(),
            name.m_parts.end(),
            std::string(),
            [](const std::string& a, const std::string& b) -> std::string
            { return a + (a.length() > 0 ? SEPARATOR_S : "") + b; });
        return os;
    }

    /**
     * @brief Get the full name string
     *
     * @return std::string Full name string in the form
     * <type>SEPARATOR<name>SEPARATOR<version>
     */
    std::string fullName() const
    {
        std::stringstream ss;
        ss << *this;
        return ss.str();
    }

    /**
     * @brief Get the parts of the name
     *
     * @return const std::vector<std::string>&
     */
    const std::vector<std::string>& parts() const { return m_parts; }
};

} // namespace base

#endif // _BASE_NAME_HPP
