#ifndef _GEO_MOCK_MANAGER_HPP
#define _GEO_MOCK_MANAGER_HPP

#include <gmock/gmock.h>

#include <geo/imanager.hpp>

namespace geo::mocks
{
class MockManager : public IManager
{
public:
    MOCK_METHOD(base::OptError, addDb, (const std::string& path, Type type), (override));
    MOCK_METHOD(base::OptError, removeDb, (const std::string& path), (override));
    MOCK_METHOD(base::OptError,
                remoteUpsertDb,
                (const std::string& path, Type type, const std::string& dbUrl, const std::string& hashUrl),
                (override));
    MOCK_METHOD(std::vector<DbInfo>, listDbs, (), (const, override));
    MOCK_METHOD(base::RespOrError<std::shared_ptr<ILocator>>, getLocator, (Type type), (const, override));
};
} // namespace geo::mocks
#endif // _GEO_MOCK_MANAGER_HPP
