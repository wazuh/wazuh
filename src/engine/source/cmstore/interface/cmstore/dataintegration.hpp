#ifndef _ICMSTORE_DATA_INTEGRATION
#define _ICMSTORE_DATA_INTEGRATION

#include <optional>
#include <stdexcept>
#include <string>
#include <tuple>
#include <vector>

#include <fmt/format.h>

#include <base/json.hpp>
#include <base/utils/generator.hpp>

#include <cmstore/categories.hpp>
#include <cmstore/detail.hpp>

/**
 * @brief DataIntegration class to represent a content manager data integration. Its the definition of an integration.
 *
 * Expected JSON format:
 * {
 *   "id": "5c1df6b6-1458-4b2e-9001-96f67a8b12c8",
 *   "title": "windows",
 *   "enabled": true|false,
 *   "category": "security",
 *   "default_parent": "85853f26-5779-469b-86c4-c47ee7d400b4", --> Optional
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
    std::optional<std::string> m_defaultParent;
    std::vector<std::string> m_kvdbsByUUID;
    std::vector<std::string> m_decodersByUUID;


public:
    ~Integration() = default;
    Integration() = delete;

    Integration(std::string uuid,
                std::string name,
                bool enabled,
                std::string category,
                std::optional<std::string> defaultParent,
                std::vector<std::string> kvdbsByUUID,
                std::vector<std::string> decodersByUUID,
                bool requireUUID = true)
        : m_uuid(std::move(uuid))
        , m_name(std::move(name))
        , m_enabled(enabled)
        , m_category(std::move(category))
        , m_defaultParent(std::move(defaultParent))
        , m_kvdbsByUUID(std::move(kvdbsByUUID))
        , m_decodersByUUID(std::move(decodersByUUID))
    {
        if (m_uuid.empty())
        {
            if (requireUUID)
            {
                throw std::runtime_error("Integration UUID cannot be empty");
            }
        }
        else
        {
            if (!base::utils::generators::isValidUUIDv4(m_uuid))
            {
                throw std::runtime_error("Integration UUID is not a valid UUIDv4: " + m_uuid);
            }
        }
        if (m_name.empty())
        {
            throw std::runtime_error("Integration name cannot be empty");
        }
        if (m_category.empty())
        {
            throw std::runtime_error("Integration category cannot be empty");
        }
        if (!cm::store::categories::exists(m_category))
        {
            throw std::runtime_error("Integration category is not valid: " + m_category);
        }

        if (m_defaultParent.has_value())
        {
            if (!base::utils::generators::isValidUUIDv4(*m_defaultParent))
            {
                throw std::runtime_error("Integration default parent is not a valid UUIDv4: " + *m_defaultParent);
            }
        }

        cm::store::detail::findDuplicateOrInvalidUUID(m_decodersByUUID, "Decoder");

        cm::store::detail::findDuplicateOrInvalidUUID(m_kvdbsByUUID, "KVDB");

        cm::store::detail::findDuplicateOrInvalidUUID(m_outputsByUUID, "Output");

    }

    static Integration fromJson(const json::Json& integrationJson, bool requireUUID)
    {

        const auto uuidOpt = integrationJson.getString(jsonintegration::PATH_KEY_ID);
        std::string uuid {};

        if (!uuidOpt.has_value())
        {
            if (requireUUID)
            {
                throw std::runtime_error("Integration JSON must have a valid id");
            }
            // requireUUID == false => uuid does not exist, will be generated later
        }
        else
        {
            uuid = *uuidOpt;
        }

        if (requireUUID && !base::utils::generators::isValidUUIDv4(uuid))
        {
            throw std::runtime_error("Integration UUID is not a valid UUIDv4: " + uuid);
        }

        auto nameOpt = integrationJson.getString(jsonintegration::PATH_KEY_NAME);
        if (!nameOpt.has_value())
        {
            throw std::runtime_error("Integration JSON must have a valid name");
        }

        auto enabledOpt = integrationJson.getBool(jsonintegration::PATH_KEY_ENABLED);
        if (!enabledOpt.has_value())
        {
            throw std::runtime_error("Integration JSON must have a valid enabled flag");
        }

        auto categoryOpt = integrationJson.getString(jsonintegration::PATH_KEY_CATEGORY);
        if (!categoryOpt.has_value())
        {
            throw std::runtime_error("Integration JSON must have a valid category");
        }

        std::size_t decoderCount = integrationJson.size(jsonintegration::PATH_KEY_DECODERS);
        std::vector<std::string> decoders;
        decoders.reserve(decoderCount);

        for (std::size_t i = 0; i < decoderCount; ++i)
        {
            auto decoderOpt = integrationJson.getString(fmt::format("{}/{}", jsonintegration::PATH_KEY_DECODERS, i));
            if (!decoderOpt.has_value())
            {
                throw std::runtime_error(fmt::format("Decoder at index {} is not a valid string", i));
            }
            decoders.push_back(decoderOpt.value());
        }

        std::size_t kvdbCount = integrationJson.size(jsonintegration::PATH_KEY_KVDBS);
        std::vector<std::string> kvdbs;
        kvdbs.reserve(kvdbCount);

        for (std::size_t i = 0; i < kvdbCount; ++i)
        {
            auto kvdbOpt = integrationJson.getString(fmt::format("{}/{}", jsonintegration::PATH_KEY_KVDBS, i));
            if (!kvdbOpt.has_value())
            {
                throw std::runtime_error(fmt::format("KVDB at index {} is not a valid string", i));
            }
            kvdbs.push_back(kvdbOpt.value());
        }

        std::optional<std::string> defaultParent = std::nullopt;
        if (auto defaultParentOpt = integrationJson.getString(jsonintegration::PATH_KEY_DEFAULT_PARENT);
            defaultParentOpt.has_value())
        {
            if (defaultParentOpt->empty())
            {
                throw std::runtime_error("Integration default parent cannot be empty");
            }
            if (!base::utils::generators::isValidUUIDv4(*defaultParentOpt))
            {
                throw std::runtime_error("Integration default parent is not a valid UUIDv4: " + *defaultParentOpt);
            }
            defaultParent = defaultParentOpt.value();
        }

        return {std::move(uuid),
                std::move(*nameOpt),
                *enabledOpt,
                std::move(*categoryOpt),
                std::move(defaultParent),
                std::move(kvdbs),
                std::move(decoders),
                requireUUID};
    }

    json::Json toJson() const
    {
        json::Json integrationJson;
        if (!m_uuid.empty())
        {
            integrationJson.setString(m_uuid, jsonintegration::PATH_KEY_ID);
        }
        integrationJson.setString(m_name, jsonintegration::PATH_KEY_NAME);
        integrationJson.setString(m_category, jsonintegration::PATH_KEY_CATEGORY);

        if (m_defaultParent.has_value())
        {
            integrationJson.setString(m_defaultParent.value(), jsonintegration::PATH_KEY_DEFAULT_PARENT);
        }

        integrationJson.setBool(m_enabled, jsonintegration::PATH_KEY_ENABLED);

        integrationJson.setArray(jsonintegration::PATH_KEY_DECODERS);
        for (std::size_t i = 0; i < m_decodersByUUID.size(); ++i)
        {
            integrationJson.setString(m_decodersByUUID[i], fmt::format("{}/{}", jsonintegration::PATH_KEY_DECODERS, i));
        }

        integrationJson.setArray(jsonintegration::PATH_KEY_KVDBS);
        for (std::size_t i = 0; i < m_kvdbsByUUID.size(); ++i)
        {
            integrationJson.setString(m_kvdbsByUUID[i], fmt::format("{}/{}", jsonintegration::PATH_KEY_KVDBS, i));
        }

        return integrationJson;
    }

    // getters
    const std::string& getCategory() const { return m_category; }
    const std::optional<std::string>& getDefaultParent() const { return m_defaultParent; }
    const bool hasDefaultParent() const { return m_defaultParent.has_value(); }
    const std::vector<std::string>& getKVDBsByUUID() const { return m_kvdbsByUUID; }
    const std::vector<std::string>& getDecodersByUUID() const { return m_decodersByUUID; }
    const std::vector<std::string>& getOutputsByUUID() const { return m_outputsByUUID; }
    const std::string& getName() const { return m_name; }
    const std::string& getUUID() const { return m_uuid; }
    bool isEnabled() const { return m_enabled; }
};

} // namespace cm::store::dataType

#endif // _ICMSTORE_DATA_INTEGRATION
