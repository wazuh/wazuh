#pragma once

#include "../core/logger.hpp"
#include "cgroup_host_mode.h"
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
                           std::string cgroupRoot = "/sys/fs/cgroup",
                           // A host constant, read once. Never per record and never
                           // inferred from an event: mixing hierarchies within one
                           // store would reintroduce the ambiguity that keying by
                           // host mode exists to remove.
                           wz_cgroup_mode_t cgroupMode = wz_cgroup_mode());

        [[nodiscard]] CgroupScan scan() const override;
        [[nodiscard]] std::optional<CgroupEntry> scanOne(std::uint64_t hostKey) const override;

    private:
        const IFileSystemWrapper& m_filesystem;
        const IFileIOUtils& m_fileIO;
        const IInodeReader& m_inodeReader;
        Logger m_logger;
        std::string m_procRoot;
        std::string m_cgroupRoot;
        wz_cgroup_mode_t m_cgroupMode;

        /// On legacy, the controller the SHARED selector picked — the same one
        /// the eBPF program is configured to read. Resolved once at construction
        /// because it is a host constant, and passed to selectCanonicalCgroup so
        /// the resolver cannot settle on a different hierarchy than the engine.
        /// Empty on unified and hybrid, where the unified id is used instead.
        std::string m_v1Controller;
    };

} // namespace wazuh::container_instances
