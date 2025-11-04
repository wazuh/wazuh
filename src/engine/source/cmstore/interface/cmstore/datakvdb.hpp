#ifndef _ICMSTORE_DATA_KVDB
#define _ICMSTORE_DATA_KVDB

#include <string>
#include <tuple>
#include <vector>

#include <base/json.hpp>
#include <base/name.hpp>
#include <base/utils/generator.hpp>
#include <base/utils/hash.hpp>

/**
 * @brief DataKVDB class to represent a content manager data key-value database. Its the definition of a KVDB.
 *
 * Expexted JSON format:
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
} // namespace jsonkvdb

class KVDB
{
private:
    std::string m_uuid;
    std::string m_name;
    json::Json m_data;

    std::string m_hash;

    void updateHash()
    {
        // Create a hash based on the KVDB content
        std::string toHash = m_data.str();
        m_hash = base::utils::hash::sha256(toHash);
    }

public:
    KVDB(std::string uuid, std::string name, json::Json&& data)
        : m_uuid(std::move(uuid))
        , m_name(std::move(name))
        , m_data(std::move(data))
    {
        updateHash();
    }

    static KVDB fromJson(const json::Json& kvdbJson)
    {
        auto uuidOpt = kvdbJson.getString(jsonkvdb::PATH_KEY_ID);
        if (!uuidOpt.has_value())
        {
            throw std::runtime_error("KVDB JSON must have a valid id");
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

        return {std::move(uuidOpt.value()), std::move(nameOpt.value()), std::move(contentOpt.value())};
    }

    json::Json toJson() const
    {
        json::Json kvdbJson;

        kvdbJson.setString(m_uuid, jsonkvdb::PATH_KEY_ID);
        kvdbJson.setString(m_name, jsonkvdb::PATH_KEY_NAME);
        kvdbJson.set(jsonkvdb::PATH_KEY_CONTENT, m_data);

        return kvdbJson;
    }

    const json::Json& getData() const { return m_data; }

    ~KVDB() = default;
};

} // namespace cm::store::dataType

#endif // _ICMSTORE_DATA_KVDB
