#ifndef _MOCKS_CM_IREADER_HPP
#define _MOCKS_CM_IREADER_HPP

#include <gmock/gmock.h>

#include <ctistore/icmreader.hpp>

namespace cti::store
{
class MockCMReader : public ICMReader
{
public:
    MOCK_METHOD(std::vector<base::Name>, getAssetList, (cti::store::AssetType type), (const, override));
    MOCK_METHOD(json::Json, getAsset, (const base::Name& name), (const, override));
    MOCK_METHOD(bool, assetExists, (const base::Name& name), (const, override));
    MOCK_METHOD(std::vector<std::string>, listKVDB, (), (const, override));
    MOCK_METHOD(std::vector<std::string>, listKVDB, (const base::Name& integrationName), (const, override));
    MOCK_METHOD(bool, kvdbExists, (const std::string& kdbName), (const, override));
    MOCK_METHOD(json::Json, kvdbDump, (const std::string& kdbName), (const, override));
    MOCK_METHOD(std::vector<base::Name>, getPolicyIntegrations, (), (const, override));
    MOCK_METHOD(json::Json, getIntegrationPolicy, (const base::Name& integrationName), (const, override));
    MOCK_METHOD(bool, integrationInPolicy, (const base::Name& integrationName), (const, override));
    MOCK_METHOD(json::Json, getPolicy, (), (const, override));
};
} // namespace cti::store


#endif // _MOCKS_CM_IREADER_HPP
