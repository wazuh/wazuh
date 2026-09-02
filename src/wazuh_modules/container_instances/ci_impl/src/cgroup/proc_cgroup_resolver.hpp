#pragma once

#include "../core/logger.hpp"
#include "i_cgroup_resolver.hpp"
#include "i_inode_reader.hpp"
#include "ifile_io_utils.hpp"
#include "ifilesystem_wrapper.hpp"

#include <string>

namespace wazuh::container_instances
{

    /// /proc walk + cgroupfs stat. Requires the host PID and cgroup namespaces
    /// (the agent is a host systemd service, so both hold by deployment model).
    class ProcCgroupResolver final : public ICgroupResolver
    {
    public:
        ProcCgroupResolver(const IFileSystemWrapper& filesystem,
                           const IFileIOUtils& fileIO,
                           const IInodeReader& inodeReader,
                           Logger logger,
                           std::string procRoot = "/proc",
                           std::string cgroupRoot = "/sys/fs/cgroup");

        [[nodiscard]] CgroupScan scan() const override;
        [[nodiscard]] std::optional<CgroupEntry> scanOne(std::uint64_t cgroupInode) const override;

    private:
        const IFileSystemWrapper& m_filesystem;
        const IFileIOUtils& m_fileIO;
        const IInodeReader& m_inodeReader;
        Logger m_logger;
        std::string m_procRoot;
        std::string m_cgroupRoot;
    };

} // namespace wazuh::container_instances
