#ifndef _ICMSTORE_DATA_KVDB
#define _ICMSTORE_DATA_KVDB

#include <string>
#include <tuple>
#include <vector>

#include <base/json.hpp>

namespace cm::store::dataType
{
class KVDB
{
private:
    std::string m_hash;
    std::tuple<std::string, std::string> m_id; // uuid, name
    json::Json m_data;

public:
    KVDB() = default;
    ~KVDB() = default;
};

} // namespace cm::store::data

#endif // _ICMSTORE_DATA_KVDB
