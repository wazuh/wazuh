#ifndef _ICMSTORE_DATA_KVDB
#define _ICMSTORE_DATA_KVDB

#include <string>
#include <tuple>
#include <vector>

#include <base/json.hpp>
#include <base/utils/generator.hpp>

/**
 * @brief DataKVDB class to represent a content manager data key-value database. Its the definition of a KVDB.
 *
 * Expected JSON format:
 * {
 *   "id": "82e215c4-988a-4f64-8d15-b98b2fc03a4f",
 *   "date": "2025-10-06T13:32:19Z",
 *   "title": "windows_kerberos_status_code_to_code_name",
 *   "author": "Wazuh Inc.",
 *   "content": {
 *     "0x0": "KDC_ERR_NONE",
 *     "0x1": "KDC_ERR_NAME_EXP",
 *     "0x2": "KDC_ERR_SERVICE_EXP",
 *     "0x3": "KDC_ERR_BAD_PVNO",
 *     "0x4": "KDC_ERR_C_OLD_MAST_KVNO",
 *     "0x5": "KDC_ERR_S_OLD_MAST_KVNO",
 *     "0x6": "KDC_ERR_C_PRINCIPAL_UNKNOWN",
 *   },
 *   "enabled": true
 * }
 */
namespace cm::store::dataType
{

namespace jsonkvdb
{
constexpr std::string_view PATH_KEY_ID = "/id";
constexpr std::string_view PATH_KEY_NAME = "/title";
constexpr std::string_view PATH_KEY_CONTENT = "/content";
constexpr std::string_view PATH_KEY_ENABLED = "/enabled";
} // namespace jsonkvdb

class KVDB
{
private:
    std::string m_uuid;
    std::string m_name;
    json::Json m_data;
    bool m_enabled;


public:
    KVDB() = delete;

    KVDB(std::string uuid, std::string name, json::Json&& data, bool enabled, bool requireUUID = true)
        : m_uuid(std::move(uuid))
        , m_name(std::move(name))
        , m_enabled(enabled)
    {
        if (m_uuid.empty())
        {
            if (requireUUID)
            {
                throw std::runtime_error("KVDB UUID cannot be empty");
            }
        }
        else
        {
            if (!base::utils::generators::isValidUUIDv4(m_uuid))
            {
                throw std::runtime_error("KVDB UUID must be a valid UUIDv4: " + m_uuid);
            }
        }
        if (m_name.empty())
        {
            throw std::runtime_error("KVDB name cannot be empty");
        }
        if (!data.isObject())
        {
            throw std::runtime_error(fmt::format("KVDB content must be a JSON object but got '{}'", data.typeName()));
        }
        m_data = std::move(data);

    }

    static KVDB fromJson(const json::Json& kvdbJson, bool requireUUID)
    {
        const auto uuidOpt = kvdbJson.getString(jsonkvdb::PATH_KEY_ID);
        std::string uuid {};

        if (!uuidOpt.has_value())
        {
            if (requireUUID)
            {
                throw std::runtime_error("KVDB JSON must have a valid id");
            }
            // requireUUID == false => uuid remains empty
        }
        else
        {
            uuid = *uuidOpt;
        }

        if (requireUUID && !base::utils::generators::isValidUUIDv4(uuid))
        {
            throw std::runtime_error("KVDB UUID is not a valid UUIDv4: " + uuid);
        }

        auto nameOpt = kvdbJson.getString(jsonkvdb::PATH_KEY_NAME);
        if (!nameOpt.has_value())
        {
            throw std::runtime_error("KVDB JSON must have a valid name");
        }

        auto contentOpt = kvdbJson.getJson(jsonkvdb::PATH_KEY_CONTENT);
        if (!contentOpt.has_value())
        {
            throw std::runtime_error("KVDB JSON must have a valid content object");
        }

        auto enabledOpt = kvdbJson.getBool(jsonkvdb::PATH_KEY_ENABLED);
        if (!enabledOpt.has_value())
        {
            throw std::runtime_error("KVDB JSON must have a valid enabled field");
        }

        return {std::move(uuid), std::move(nameOpt.value()), std::move(contentOpt.value()), *enabledOpt, requireUUID};
    }

    json::Json toJson() const
    {
        json::Json kvdbJson;

        if (!m_uuid.empty())
        {
            kvdbJson.setString(m_uuid, jsonkvdb::PATH_KEY_ID);
        }

        kvdbJson.setString(m_name, jsonkvdb::PATH_KEY_NAME);
        kvdbJson.setBool(m_enabled, jsonkvdb::PATH_KEY_ENABLED);
        kvdbJson.set(jsonkvdb::PATH_KEY_CONTENT, m_data);

        return kvdbJson;
    }

    const json::Json& getData() const { return m_data; }
    const std::string& getUUID() const { return m_uuid; }
    const std::string& getName() const { return m_name; }
    bool isEnabled() const { return m_enabled; }

    ~KVDB() = default;
};

} // namespace cm::store::dataType

#endif // _ICMSTORE_DATA_KVDB
