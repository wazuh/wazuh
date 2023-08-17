#ifndef _STORE_NAMESPACEID_HPP
#define _STORE_NAMESPACEID_HPP

#include <string>

#include <name.hpp>

namespace store
{

class NamespaceId
{
public:
    static const std::size_t PARTS_NAMESPACE_SIZE = 1;

private:
    base::Name m_id;

    void assertValid()
    {
        if (m_id.parts().size() != PARTS_NAMESPACE_SIZE)
        {
            throw std::invalid_argument("NamespaceId must have only one part, cannot be empty and cannot contain '/'");
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
    explicit operator std::string() const { return m_id.parts()[0]; }

    /**
     * @brief Get the base::Name of the NamespaceId
     *
     * @return const base::Name&
     */
    const base::Name& name() const { return m_id; }

    /**
     * @brief Get the string representation of the NamespaceId
     *
     * @return const std::string&
     */
    const std::string& str() const { return m_id.parts()[0]; }

    /**
     * @brief Operator < to compare two NamespaceId
     *
     * @param other NamespaceId to compare
     * @return true
     * @return false
     */
    bool operator<(const NamespaceId& other) const { return m_id < other.m_id; }
};

} // namespace store

// hash function for NamespaceId
namespace std
{
template <>
struct hash<store::NamespaceId>
{
    std::size_t operator()(const store::NamespaceId& k) const
    {
        return hash<base::Name>()(k.name());
    }
};
} // namespace std

#endif // _STORE_NAMESPACEID_HPP
