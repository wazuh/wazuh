#ifndef _ICMSTORE_DATA_INTEGRATION
#define _ICMSTORE_DATA_INTEGRATION

#include <string>
#include <tuple>
#include <vector>

#include <base/json.hpp>
#include <base/name.hpp>
#include <base/utils/generator.hpp>
#include <base/utils/hash.hpp>

/**
 * @brief DataIntegration class to represent a content manager data integration. Its the definition of an integration.
 *
 * Expexted JSON format:
 * {
 *   "id": "5c1df6b6-1458-4b2e-9001-96f67a8b12c8",
 *   "title": "windows",
 *   "enabled": true|false,
 *   "category": "ossec",
 *   "default_parent": "docoder/windows/0", --> Optional
 *   "decoders":
 *   [
 *     "85853f26-5779-469b-86c4-c47ee7d400b4",
 *     "4aa06596-5ba9-488c-8354-2475705e1257",
 *     "4da71af3-fff5-4b67-90d6-51db9e15bc47",
 *     "6f8bd7d2-8516-4b2b-a6f1-cc924513c404",
 *   ],
 *   "kvdbs": []
 * }
 */
namespace cm::store::dataType
{

namespace jsonintegration
{
constexpr std::string_view PATH_KEY_ID = "/id";
constexpr std::string_view PATH_KEY_NAME = "/title";
constexpr std::string_view PATH_KEY_ENABLED = "/enabled";
constexpr std::string_view PATH_KEY_CATEGORY = "/category";
constexpr std::string_view PATH_KEY_DEFAULT_PARENT = "/default_parent";
constexpr std::string_view PATH_KEY_DECODERS = "/decoders";
constexpr std::string_view PATH_KEY_KVDBS = "/kvdbs";
} // namespace jsonintegration

class Integration
{
private:
    std::string m_uuid;
    std::string m_name;
    bool m_enabled;
    std::string m_category;
    std::optional<base::Name> m_defaultParent;
    std::vector<std::string> m_kvdbsByUUID;
    std::vector<std::string> m_decodersByUUID;

    std::string m_hash;

    void updateHash()
    {
        // Create a hash based on the name, category, decoders and kvdbs UUIDs
        std::string toHash = m_name + m_category;
        toHash.reserve(toHash.length() + 1
                       + (m_decodersByUUID.size() + m_kvdbsByUUID.size()) * base::utils::generators::UUID_V4_LENGTH);
        for (const auto& uuid : m_decodersByUUID)
        {
            toHash += uuid;
        }
        for (const auto& uuid : m_kvdbsByUUID)
        {
            toHash += uuid;
        }
        toHash += m_enabled ? "1" : "0";
        m_hash = base::utils::hash::sha256(toHash);
    }

public:
    ~Integration() = default;

    Integration() = default;

    static Integration fromJson(const json::Json& integrationJson)
    {
        Integration integration = {};

        auto uuidOpt = integrationJson.getString(jsonintegration::PATH_KEY_ID);
        if (!uuidOpt.has_value())
        {
            throw std::runtime_error("Integration JSON must have a valid id");
        }
        integration.m_uuid = uuidOpt.value();

        auto nameOpt = integrationJson.getString(jsonintegration::PATH_KEY_NAME);
        if (!nameOpt.has_value())
        {
            throw std::runtime_error("Integration JSON must have a valid name");
        }
        integration.m_name = nameOpt.value();

        auto enabledOpt = integrationJson.getBool(jsonintegration::PATH_KEY_ENABLED);
        if (!enabledOpt.has_value())
        {
            throw std::runtime_error("Integration JSON must have a valid enabled flag");
        }
        integration.m_enabled = enabledOpt.value();

        auto categoryOpt = integrationJson.getString(jsonintegration::PATH_KEY_CATEGORY);
        if (!categoryOpt.has_value())
        {
            throw std::runtime_error("Integration JSON must have a valid category");
        }
        integration.m_category = categoryOpt.value();

        std::size_t decoderCount = integrationJson.size(jsonintegration::PATH_KEY_DECODERS);
        integration.m_decodersByUUID.reserve(decoderCount);

        for (std::size_t i = 0; i < decoderCount; ++i)
        {
            auto decoderOpt = integrationJson.getString(fmt::format("{}/{}", jsonintegration::PATH_KEY_DECODERS, i));
            if (!decoderOpt.has_value())
            {
                throw std::runtime_error(fmt::format("Decoder at index {} is not a valid string", i));
            }
            integration.m_decodersByUUID.push_back(decoderOpt.value());
        }

        std::size_t kvdbCount = integrationJson.size(jsonintegration::PATH_KEY_KVDBS);
        integration.m_kvdbsByUUID.reserve(kvdbCount);

        for (std::size_t i = 0; i < kvdbCount; ++i)
        {
            auto kvdbOpt = integrationJson.getString(fmt::format("{}/{}", jsonintegration::PATH_KEY_KVDBS, i));
            if (!kvdbOpt.has_value())
            {
                throw std::runtime_error(fmt::format("KVDB at index {} is not a valid string", i));
            }
            integration.m_kvdbsByUUID.push_back(kvdbOpt.value());
        }

        try
        {
            if (auto defaultParentOpt = integrationJson.getString(jsonintegration::PATH_KEY_DEFAULT_PARENT);
                defaultParentOpt.has_value())
            {
                integration.m_defaultParent = base::Name(defaultParentOpt.value());
            }
        }
        catch (const std::exception& e)
        {
            throw std::runtime_error(fmt::format("Error getting integration default parent: {}", e.what()));
        }
        integration.updateHash();
        return integration;
    }

    json::Json toJson() const
    {
        json::Json integrationJson;

        integrationJson.setString(jsonintegration::PATH_KEY_ID, m_uuid);
        integrationJson.setString(jsonintegration::PATH_KEY_NAME, m_name);
        integrationJson.setString(jsonintegration::PATH_KEY_CATEGORY, m_category);

        if (m_defaultParent.has_value())
        {
            integrationJson.setString(jsonintegration::PATH_KEY_DEFAULT_PARENT, m_defaultParent->toStr());
        }

        integrationJson.setArray(jsonintegration::PATH_KEY_DECODERS);
        integrationJson.setArray(jsonintegration::PATH_KEY_KVDBS);

        for (std::size_t i = 0; i < m_decodersByUUID.size(); ++i)
        {
            integrationJson.setString(fmt::format("{}/{}", jsonintegration::PATH_KEY_DECODERS, i), m_decodersByUUID[i]);
        }

        for (std::size_t i = 0; i < m_kvdbsByUUID.size(); ++i)
        {
            integrationJson.setString(fmt::format("{}/{}", jsonintegration::PATH_KEY_KVDBS, i), m_kvdbsByUUID[i]);
        }

        return integrationJson;
    }

    // getters
    const std::string& getCategory() const { return m_category; }
    const std::optional<base::Name>& getDefaultParent() const { return m_defaultParent; }
    const std::vector<std::string>& getKVDBsByUUID() const { return m_kvdbsByUUID; }
    const std::vector<std::string>& getDecodersByUUID() const { return m_decodersByUUID; }
    const std::string& getHash() const { return m_hash; }
    const std::string& getName() const { return m_name; }
    const std::string& getUUID() const { return m_uuid; }
    bool isEnabled() const { return m_enabled; }

};

} // namespace cm::store::dataType

#endif // _ICMSTORE_DATA_KVDB
