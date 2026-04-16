#ifndef GEO_MOCK_MANAGER_HPP
#define GEO_MOCK_MANAGER_HPP

#include <gmock/gmock.h>

#include <geo/imanager.hpp>

namespace geo::mocks
{
class MockManager : public IManager
{
public:
    MOCK_METHOD(void,
                remoteUpsert,
                (const std::string& manifestUrl, const std::string& cityPath, const std::string& asnPath),
                (override));
    MOCK_METHOD(std::vector<DbInfo>, listDbs, (), (const, override));
    MOCK_METHOD(Result<std::shared_ptr<ILocator>>, getLocator, (Type type), (const, override));
};
} // namespace geo::mocks
#endif // GEO_MOCK_MANAGER_HPP
