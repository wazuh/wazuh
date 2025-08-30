#pragma once

#include <sca_impl.hpp>

#include <mock_dbsync.hpp>
#include <mock_filesystem_wrapper.hpp>

class SCAMock : public SecurityConfigurationAssessment
{
    public:
        SCAMock(std::shared_ptr<IDBSync> dBSync = nullptr, std::shared_ptr<IFileSystemWrapper> fileSystemWrapper = nullptr)
            : SecurityConfigurationAssessment("db_path", dBSync, fileSystemWrapper)
        {}

        std::vector<std::unique_ptr<ISCAPolicy>>& GetPolicies()
        {
            return m_policies;
        }
};
