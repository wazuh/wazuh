#ifndef _MOCKS_CM_IREADER_HPP
#define _MOCKS_CM_IREADER_HPP

#include <gmock/gmock.h>

#include <ctistore/icmreader.hpp>

namespace cti::store
{
class MockCMReader : public ICMReader
{
public:
    // Asset operations
    MOCK_METHOD(std::vector<base::Name>, getAssetList, (cti::store::AssetType type), (const, override));
    MOCK_METHOD(json::Json, getAsset, (const base::Name& name), (const, override));
    MOCK_METHOD(bool, assetExists, (const base::Name& name), (const, override));
    MOCK_METHOD(std::string, resolvNameFromUUID, (const std::string& uuid), (const, override));

    // KVDB operations
    MOCK_METHOD(std::vector<std::string>, listKVDB, (), (const, override));
    MOCK_METHOD(std::vector<std::string>, listKVDB, (const base::Name& integrationName), (const, override));
    MOCK_METHOD(bool, kvdbExists, (const std::string& kdbName), (const, override));
    MOCK_METHOD(json::Json, kvdbDump, (const std::string& kdbName), (const, override));

    // Policy operations
    MOCK_METHOD(std::vector<base::Name>, getPolicyIntegrationList, (), (const, override));
    MOCK_METHOD(base::Name, getPolicyDefaultParent, (), (const, override));
    MOCK_METHOD(json::Json, getPolicy, (const base::Name& name), (const, override));
    MOCK_METHOD(std::vector<base::Name>, getPolicyList, (), (const, override));
    MOCK_METHOD(bool, policyExists, (const base::Name& name), (const, override));
};
} // namespace cti::store


#endif // _MOCKS_CM_IREADER_HPP
