#ifndef _ICMSTORE_DATA_INTEGRATION
#define _ICMSTORE_DATA_INTEGRATION

#include <string>
#include <tuple>
#include <vector>

#include <base/json.hpp>
#include <base/name.hpp>

namespace cm::store::dataType
{
class Integration
{
    private:
    std::vector<std::tuple<base::Name, std::string>> m_decoders;
    std::vector<std::tuple<base::Name, std::string>> m_kvdbs;
    std::string m_category;

    std::optional<base::Name> m_defaultParent;
    std::string m_hash;
    std::tuple<std::string, std::string> m_id; // uuid, name

public:
    // Add asset
    // Remove Asset
    // getAsJSON
    Integration() = default;
    ~Integration() = default;

    //getters
    const std::vector<std::tuple<base::Name, std::string>>& getDecoders() const { return m_decoders; }
    const std::vector<std::tuple<base::Name, std::string>>& getKVDBs() const { return m_kvdbs; }
    const std::string& getCategory() const { return m_category; }
    const std::optional<base::Name>& getDefaultParent() const { return m_defaultParent; }
    const std::string& getHash() const { return m_hash; }
    const std::tuple<std::string, std::string>& getId() const { return m_id; }
};


} // namespace cm::store::data

#endif // _ICMSTORE_DATA_KVDB
