#ifndef GEO_MOCK_LOCATOR_HPP
#define GEO_MOCK_LOCATOR_HPP

#include <gmock/gmock.h>

#include <geo/ilocator.hpp>

namespace geo::mocks
{
class MockLocator : public ILocator
{
public:
    MOCK_METHOD(Result<std::string>, getString, (const std::string& ip, const DotPath& path), (override));
    MOCK_METHOD(Result<uint32_t>, getUint32, (const std::string& ip, const DotPath& path), (override));
    MOCK_METHOD(Result<double>, getDouble, (const std::string& ip, const DotPath& path), (override));
    MOCK_METHOD(Result<json::Json>, getAsJson, (const std::string& ip, const DotPath& path), (override));
    MOCK_METHOD(Result<json::Json>, getAll, (const std::string& ip), (override));
};
} // namespace geo::mocks
#endif // GEO_MOCK_LOCATOR_HPP
