#ifndef _MMDB_MOCK_RESULT_HPP
#define _MMDB_MOCK_RESULT_HPP

#include <gmock/gmock.h>

#include <mmdb/iresult.hpp>

namespace mmdb
{
class MockResult : public IResult
{
public:
    MOCK_METHOD(bool, hasData, (), (const, override));
    MOCK_METHOD(base::RespOrError<std::string>, getString, (const DotPath& path), (const, override));
    MOCK_METHOD(base::RespOrError<uint32_t>, getUint32, (const DotPath& path), (const, override));
    MOCK_METHOD(base::RespOrError<double>, getDouble, (const DotPath& path), (const, override));
    MOCK_METHOD(base::RespOrError<json::Json>, getAsJson, (const DotPath& path), (const, override));
    MOCK_METHOD(json::Json, mmDump, (), (const, override));
};
} // namespace mmdb

#endif // _MMDB_MOCK_RESULT_HPP
