#ifndef _KVDB_MOCK_KVDB_HANDLER_HPP
#define _KVDB_MOCK_KVDB_HANDLER_HPP

#include <gmock/gmock.h>

#include <kvdb/ikvdbhandler>

namespace kvdb::mocks
{

/******************************************************************************/
// Helper functions to mock method responses
/******************************************************************************/
inline base::OptError kvdbError()
{
    return base::Error {"Mocked kvdb error"};
}

inline base::OptError kvdbOk()
{
    return std::nullopt;
}

/******************************************************************************/
// Mock classes
/******************************************************************************/
class MockKVDBHandler : public kvdb::IKVDBHandler
{
public:
    MOCK_METHOD((base::OptError), set, (const std::string& key, const std::string& value), (override));
    MOCK_METHOD((base::OptError), set, (const std::string& key, const json::Json& value), (override));
    MOCK_METHOD((base::OptError), add, (const std::string& key), (override));
    MOCK_METHOD((base::OptError), remove, (const std::string& key), (override));
    MOCK_METHOD((base::RespOrError<bool>), contains, (const std::string& key), (override));
    MOCK_METHOD((base::RespOrError<std::string>), get, (const std::string& key), (override));
    MOCK_METHOD((base::RespOrError<std::list<std::pair<std::string, std::string>>>, base::Error >),
                dump,
                (const unsigned int page, const unsigned int records),
                (override));
    MOCK_METHOD((base::RespOrError<std::list<std::pair<std::string, std::string>>>, base::Error >),
                dump,
                (),
                (override));
    MOCK_METHOD((base::RespOrError<std::list<std::pair<std::string, std::string>>>, base::Error >),
                search,
                (const std::string& prefix, const unsigned int page, const unsigned int records),
                (override));
    MOCK_METHOD((base::RespOrError<std::list<std::pair<std::string, std::string>>>, base::Error >),
                search,
                (const std::string& prefix),
                (override));
};

} // namespace kvdb::mocks

#endif // _KVDB_MOCK_KVDB_HANDLER_HPP
