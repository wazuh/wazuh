#pragma once

#include <sca_policy_loader.hpp>
#include <mock_dbsync.hpp>

class ScaPolicyLoaderMock : public SCAPolicyLoader
{
    public:
        ScaPolicyLoaderMock(std::shared_ptr<IDBSync> dBSync = nullptr) : SCAPolicyLoader({}, nullptr, dBSync) {}

        nlohmann::json NormalizeData(nlohmann::json data)
        {
            return SCAPolicyLoader::NormalizeData(data);
        }

        nlohmann::json NormalizeDataWithChecksum(nlohmann::json data, const std::string& tableName)
        {
            return SCAPolicyLoader::NormalizeDataWithChecksum(data, tableName);
        }

        void UpdateCheckResult(const nlohmann::json& check)
        {
            SCAPolicyLoader::UpdateCheckResult(check);
        }

        MOCK_METHOD(void, loadPolicies, (const std::string&), (const));
        MOCK_METHOD(void, loadChecks, (const std::string&), (const));
};
