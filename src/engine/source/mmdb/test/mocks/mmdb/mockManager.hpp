#ifndef _MMDB_MOCK_MANAGER_HPP
#define _MMDB_MOCK_MANAGER_HPP

#include <gmock/gmock.h>

#include <mmdb/mockManager.hpp>

namespace mmdb
{
class MockManager : public IManager
{
public:
    MOCK_METHOD(void, addHandler, (const std::string& name, const std::string& mmdbPath), (override));
    MOCK_METHOD(void, removeHandler, (const std::string& name), (override));
    MOCK_METHOD(base::RespOrError<std::shared_ptr<IHandler>>, getHandler, (const std::string& name), (const, override));
};
} // namespace mmdb

#endif // _MMDB_MOCK_MANAGER_HPP
