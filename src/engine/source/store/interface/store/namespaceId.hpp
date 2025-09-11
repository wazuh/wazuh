#ifndef _STORE_NAMESPACEID_HPP
#define _STORE_NAMESPACEID_HPP

#include <string>

#include <base/name.hpp>

namespace store
{

/**
 * @brief Represents a namespace identifier with only one part.
 *
 * A NamespaceId is a unique identifier for a namespace with only one part. It is represented as a base::Name object.
 *
 * @note NamespaceId must have only one part and cannot be empty.
 */
class NamespaceId
{
public:
    static const std::size_t PARTS_NAMESPACE_SIZE = 1; ///< NamespaceId must have only one part

private:
    base::Name m_id; ///< NamespaceId as a base::Name

    /**
     * @brief Assert that the NamespaceId is valid
     *
     * @throws std::invalid_argument if the NamespaceId is invalid
     */
    void assertValid()
    {
        if (m_id.parts().size() != PARTS_NAMESPACE_SIZE || m_id.parts()[0].empty())
        {
            throw std::runtime_error("NamespaceId must have only one part and cannot be empty");
        }
    }

public:
    NamespaceId() = default;
    ~NamespaceId() = default;

    /**
     * @brief Constructs a NamespaceId object with the given id.
     *
     * @param id The id of the namespace.
     */
    NamespaceId(const std::string& id)
        : m_id(id)
    {
        assertValid();
    }

    /**
     * @brief Constructs a NamespaceId object with the given id.
     *
     * @param id The id of the namespace.
     */
    NamespaceId(const char* id)
        : m_id(id)
    {
        assertValid();
    }

    /**
     * @brief Constructs a NamespaceId object with the given id.
     *
     * @param id The id of the namespace.
     */
    explicit NamespaceId(const base::Name& id)
        : m_id(id)
    {
        assertValid();
    }

    /**
     * @brief Converts a base::Name object to a NamespaceId object.
     *
     * @param name The base::Name object to convert.
     * @return A base::RespOrError object containing either a NamespaceId object or an error message.
     */
    static base::RespOrError<NamespaceId> fromName(const base::Name& name)
    {
        NamespaceId namespaceId;
        try
        {
            namespaceId = NamespaceId(name);
        }
        catch (const std::invalid_argument& e)
        {
            return base::Error {e.what()};
        }

        return namespaceId;
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
template<>
struct hash<store::NamespaceId>
{
    std::size_t operator()(const store::NamespaceId& k) const { return hash<base::Name>()(k.name()); }
};
} // namespace std

#endif // _STORE_NAMESPACEID_HPP
