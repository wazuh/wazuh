#include "proc_cgroup_resolver.hpp"

#include "cgroup_parse.hpp"

#include <algorithm>
#include <optional>
#include <unordered_map>
#include <utility>

namespace wazuh::container_instances
{

    namespace
    {

        bool isAllDigits(const std::string& text)
        {
            return !text.empty() &&
                   std::all_of(text.begin(), text.end(), [](unsigned char c) { return std::isdigit(c) != 0; });
        }

    } // namespace

    ProcCgroupResolver::ProcCgroupResolver(const IFileSystemWrapper& filesystem,
                                           const IFileIOUtils& fileIO,
                                           const IInodeReader& inodeReader,
                                           Logger logger,
                                           std::string procRoot,
                                           std::string cgroupRoot)
        : m_filesystem(filesystem)
        , m_fileIO(fileIO)
        , m_inodeReader(inodeReader)
        , m_logger(std::move(logger))
        , m_procRoot(std::move(procRoot))
        , m_cgroupRoot(std::move(cgroupRoot))
    {
    }

    CgroupScan ProcCgroupResolver::scan() const
    {
        CgroupScan result;
        // One stat per distinct cgroup path, not per process.
        std::unordered_map<std::string, std::uint64_t> inodeByPath;

        for (const auto& entry : m_filesystem.list_directory(m_procRoot))
        {
            if (!isAllDigits(entry.filename().string()))
            {
                continue;
            }

            std::optional<std::string> cgroupPath;
            try
            {
                m_fileIO.readLineByLine(entry / "cgroup",
                                        [&cgroupPath](const std::string& line)
                                        {
                                            cgroupPath = parseCgroupV2Line(line);
                                            return !cgroupPath.has_value(); // Stop at the v2 line.
                                        });
            }
            catch (const std::exception&)
            {
                continue; // Process exited mid-scan: normal.
            }

            if (!cgroupPath || *cgroupPath == "/")
            {
                continue;
            }

            auto pathIt = inodeByPath.find(*cgroupPath);
            if (pathIt == inodeByPath.end())
            {
                const auto inode = m_inodeReader.inodeOf(m_cgroupRoot + *cgroupPath);
                if (!inode)
                {
                    continue; // cgroup vanished between read and stat.
                }
                pathIt = inodeByPath.emplace(*cgroupPath, *inode).first;

                result.allInodes.insert(*inode);
                if (auto match = extractContainerId(*cgroupPath))
                {
                    CgroupEntry containerEntry;
                    containerEntry.containerId = std::move(match->containerId);
                    containerEntry.inode = *inode;
                    containerEntry.hint = match->hint;
                    containerEntry.cgroupPath = *cgroupPath;
                    result.containers.push_back(std::move(containerEntry));
                }
            }
        }

        return result;
    }

    std::optional<CgroupEntry> ProcCgroupResolver::scanOne(std::uint64_t cgroupInode) const
    {
        const auto snapshot = scan();

        for (const auto& container : snapshot.containers)
        {
            if (container.inode == cgroupInode)
            {
                return container;
            }
        }

        if (snapshot.allInodes.count(cgroupInode) > 0)
        {
            CgroupEntry hostEntry; // Observed, but not a container: host-process evidence.
            hostEntry.inode = cgroupInode;
            return hostEntry;
        }

        return std::nullopt;
    }

} // namespace wazuh::container_instances
