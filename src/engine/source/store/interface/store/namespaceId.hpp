#ifndef _STORE_NAMESPACEID_HPP
#define _STORE_NAMESPACEID_HPP

#include <string>

#include <name.hpp>

namespace store
{

class NamespaceId
{
private:
    std::string m_id;

    void assertValid()
    {
        if (m_id.empty())
        {
            throw std::runtime_error("Namespace id cannot be empty");
        }

        if (m_id.find(base::Name::SEPARATOR_C) != std::string::npos)
        {
            throw std::runtime_error(
                fmt::format("Namespace id cannot contain the separator '{}'", base::Name::SEPARATOR_C));
        }
    }

public:
    NamespaceId() = default;
    ~NamespaceId() = default;

    explicit NamespaceId(const std::string& id)
        : m_id(id)
    {
        assertValid();
    }
    explicit NamespaceId(const char* id)
        : m_id(id)
    {
        assertValid();
    }

    NamespaceId(const NamespaceId& other)
        : m_id(other.m_id)
    {
    }
    NamespaceId(NamespaceId&& other) noexcept
        : m_id(std::move(other.m_id))
    {
    }

    NamespaceId& operator=(const NamespaceId& other)
    {
        if (this != &other)
        {
            m_id = other.m_id;
        }
        return *this;
    }
    NamespaceId& operator=(NamespaceId&& other) noexcept
    {
        if (this != &other)
        {
            m_id = std::move(other.m_id);
        }
        return *this;
    }

    friend bool operator==(const NamespaceId& lhs, const NamespaceId& rhs) { return lhs.m_id == rhs.m_id; }
    friend bool operator!=(const NamespaceId& lhs, const NamespaceId& rhs) { return !(lhs == rhs); }

    friend std::ostream& operator<<(std::ostream& os, const NamespaceId& obj) { return os << obj.m_id; }

    /**
     * @brief Implicit conversion to std::string
     *
     * @return std::string
     */
    explicit operator std::string() const { return m_id; }

    /**
     * @brief Get the string representation of the NamespaceId
     *
     * @return const std::string&
     */
    const std::string& str() const { return m_id; }
};

} // namespace store

#endif // _STORE_NAMESPACEID_HPP