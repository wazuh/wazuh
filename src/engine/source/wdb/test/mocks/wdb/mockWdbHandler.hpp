#ifndef _WDB_MOCK_WDB_HANDLER_HPP
#define _WDB_MOCK_WDB_HANDLER_HPP

#include <gmock/gmock.h>

#include <wdb/iwdbHandler.hpp>

namespace wazuhdb::mocks
{

using QueryRes = std::tuple<wazuhdb::QueryResultCodes, std::optional<std::string>>;

inline QueryRes okQueryRes(const std::string message = "")
{
    return QueryRes {wazuhdb::QueryResultCodes::OK, message};
}

inline QueryRes errorQueryRes(const std::string message = "")
{
    return QueryRes {wazuhdb::QueryResultCodes::ERROR, message};
}

inline QueryRes unknownQueryRes(const std::string message = "")
{
    return QueryRes {wazuhdb::QueryResultCodes::UNKNOWN, message};
}

inline QueryRes dueQueryRes(const std::string message = "")
{
    return QueryRes {wazuhdb::QueryResultCodes::DUE, message};
}

inline QueryRes ignoreQueryRes(const std::string message = "")
{
    return QueryRes {wazuhdb::QueryResultCodes::IGNORE, message};
}

class MockWdbHandler : public wazuhdb::IWDBHandler
{
public:
    MOCK_METHOD(void, connect, (), (override));
    MOCK_METHOD(std::string, query, (const std::string& query), (override));
    MOCK_METHOD(std::string, tryQuery, (const std::string& query, uint32_t attempts), (noexcept, override));
    MOCK_METHOD((std::tuple<wazuhdb::QueryResultCodes, std::optional<std::string>>),
                parseResult,
                (const std::string& result),
                (const, noexcept, override));
    MOCK_METHOD((std::tuple<wazuhdb::QueryResultCodes, std::optional<std::string>>),
                queryAndParseResult,
                (const std::string& query),
                (override));
    MOCK_METHOD((std::tuple<wazuhdb::QueryResultCodes, std::optional<std::string>>),
                tryQueryAndParseResult,
                (const std::string& query, uint32_t attempts),
                (noexcept, override));
    MOCK_METHOD(size_t, getQueryMaxSize, (), (const, noexcept, override));
};
} // namespace wazuhdb::mocks
#endif // _WDB_MOCK_WDB_HANDLER_HPP
