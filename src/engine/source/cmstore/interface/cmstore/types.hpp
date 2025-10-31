#ifndef _CMSTORE_ITYPES
#define _CMSTORE_ITYPES

#include <algorithm>
#include <cstdint>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

#include <cmstore/dataintegration.hpp>
#include <cmstore/datakvdb.hpp>
#include <cmstore/datapolicy.hpp>

namespace cm::store
{

enum class ResourceType : uint8_t
{
    UNDEFINED = 0,
    DECODER = 1,
    OUTPUT = 2,
    RULE = 3,
    INTEGRATION = 4,
    KVDB = 5
};

constexpr std::string_view RESOURCE_TYPE_UNDEFINED_STR = "undefined";
constexpr std::string_view RESOURCE_TYPE_DECODER_STR = "decoder";
constexpr std::string_view RESOURCE_TYPE_OUTPUT_STR = "output";
constexpr std::string_view RESOURCE_TYPE_RULE_STR = "rule";
constexpr std::string_view RESOURCE_TYPE_INTEGRATION_STR = "integration";
constexpr std::string_view RESOURCE_TYPE_KVDB_STR = "kvdb";

constexpr ResourceType resourceTypeFromString(std::string_view typeStr)
{
    if (typeStr == RESOURCE_TYPE_DECODER_STR)
    {
        return ResourceType::DECODER;
    }

    if (typeStr == RESOURCE_TYPE_OUTPUT_STR)
    {
        return ResourceType::OUTPUT;
    }

    if (typeStr == RESOURCE_TYPE_RULE_STR)
    {
        return ResourceType::RULE;
    }

    if (typeStr == RESOURCE_TYPE_INTEGRATION_STR)
    {
        return ResourceType::INTEGRATION;
    }

    if (typeStr == RESOURCE_TYPE_KVDB_STR)
    {
        return ResourceType::KVDB;
    }

    return ResourceType::UNDEFINED;
}

constexpr std::string_view resourceTypeToString(ResourceType type)
{
    switch (type)
    {
        case ResourceType::DECODER: return RESOURCE_TYPE_DECODER_STR;
        case ResourceType::OUTPUT: return RESOURCE_TYPE_OUTPUT_STR;
        case ResourceType::RULE: return RESOURCE_TYPE_RULE_STR;
        case ResourceType::KVDB: return RESOURCE_TYPE_KVDB_STR;
        case ResourceType::INTEGRATION: return RESOURCE_TYPE_INTEGRATION_STR;
        default: return RESOURCE_TYPE_UNDEFINED_STR;
    }
}

/**
 * @brief TransaccionLock class to manage transaction locks in the content manager store.
 *
 * This object should be used to ensure that transactions are properly locked and unlocked
 * during operations that require exclusive access to the content manager store.
 *
 * This locks the transaction on creation and releases it on destruction.
 *
 * @NOTE: Implementation details are to be defined.
 */
// class TransaccionLock
// {
// public:
//     // TransaccionLock(bool exclusive = false);
//     TransaccionLock() = default;
//     ~TransaccionLock() = default;
// };

class NamespaceId
{
private:
    std::string m_namespace;

public:
    NamespaceId() = delete;
    NamespaceId(std::string_view ns)
        : m_namespace(ns)
    {
        if (!isValidName(m_namespace))
        {
            throw std::runtime_error("Invalid namespace ID: " + m_namespace);
        }
    }

    inline const std::string& toStr() const { return m_namespace; }

    // Cast operators
    explicit operator const std::string&() const { return m_namespace; }
    explicit operator std::string_view() const { return m_namespace; }
    // Comparison operators
    bool operator==(const NamespaceId& other) const { return m_namespace == other.m_namespace; }
    bool operator!=(const NamespaceId& other) const { return m_namespace != other.m_namespace; }

    static inline bool isValidName(std::string_view ns)
    {
        if (ns.empty())
        {
            return false;
        }
        return std::all_of(ns.begin(), ns.end(), [](char c) { return std::isalnum(c) || c == '_'; });
        return true;
    }
};

} // namespace cm::store

#endif // _CMSTORE_ITYPES
