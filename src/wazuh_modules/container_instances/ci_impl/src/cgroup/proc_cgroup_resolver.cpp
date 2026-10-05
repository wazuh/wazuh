#include "proc_cgroup_resolver.hpp"

#include "cgroup_parse.hpp"

#include "../core/host_key.hpp"

#include <algorithm>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

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
                                           std::string cgroupRoot,
                                           wz_cgroup_mode_t cgroupMode)
        : m_filesystem(filesystem)
        , m_fileIO(fileIO)
        , m_inodeReader(inodeReader)
        , m_logger(std::move(logger))
        , m_procRoot(std::move(procRoot))
        , m_cgroupRoot(std::move(cgroupRoot))
        , m_cgroupMode(cgroupMode)
    {
    }

    CgroupScan ProcCgroupResolver::scan() const
    {
        CgroupScan result;

        /* What is accumulated per distinct cgroup, rather than per process.
         *
         * `lowestPid` is the reason this is an aggregate at all. A container's
         * mount-namespace inode is read from a process, and every process in a
         * container normally shares one — but `unshare -m` inside the container
         * breaks that, and whichever process the /proc walk happened to reach
         * first would then decide the container's key. Taking the lowest host
         * pid in the cgroup makes the choice deterministic and picks the
         * container's init, which is the process that defines the namespace the
         * others were born into. */
        struct Aggregate
        {
            std::uint64_t inode {0};
            std::uint64_t mntNsInode {0};
            unsigned long lowestPid {0};
            std::string cgroupPath;
            std::string keyController;
        };

        std::unordered_map<std::string, Aggregate> byMountPath;

        for (const auto& entry : m_filesystem.list_directory(m_procRoot))
        {
            const auto pidText = entry.filename().string();
            if (!isAllDigits(pidText))
            {
                continue;
            }

            std::vector<CgroupLine> lines;
            try
            {
                m_fileIO.readLineByLine(entry / "cgroup",
                                        [&lines](const std::string& line)
                                        {
                                            if (auto parsed = parseCgroupLine(line))
                                            {
                                                lines.push_back(std::move(*parsed));
                                            }
                                            return true; // Every line: the one we want depends on the host.
                                        });
            }
            catch (const std::exception&)
            {
                continue; // Process exited mid-scan: normal.
            }

            const auto selection = selectCanonicalCgroup(lines, m_cgroupMode);
            if (!selection || selection->path == "/")
            {
                continue;
            }

            // The v1 controller hierarchies are separate mounts, so the path in
            // /proc/<pid>/cgroup is relative to the controller's own mount point
            // and not to the cgroup root.
            const auto mountPath = selection->mountSubdir.empty()
                                       ? m_cgroupRoot + selection->path
                                       : m_cgroupRoot + "/" + selection->mountSubdir + selection->path;

            unsigned long pid = 0;
            try
            {
                pid = std::stoul(pidText);
            }
            catch (const std::exception&)
            {
                continue;
            }

            auto it = byMountPath.find(mountPath);
            if (it == byMountPath.end())
            {
                const auto inode = m_inodeReader.inodeOf(mountPath);
                if (!inode)
                {
                    continue; // cgroup vanished between read and stat.
                }

                Aggregate aggregate;
                aggregate.inode = *inode;
                aggregate.cgroupPath = selection->path;
                aggregate.keyController = selection->controller;
                it = byMountPath.emplace(mountPath, std::move(aggregate)).first;
            }

            if (it->second.lowestPid == 0 || pid < it->second.lowestPid)
            {
                // One extra stat per process, on a walk that already does an open
                // and a read per process. Read on EVERY host, not only where it
                // is the key, so the two hierarchies' paths stay identical and a
                // v2 host can cross-check attribution.
                if (const auto mntNs = m_inodeReader.inodeOf((entry / "ns" / "mnt").string()))
                {
                    it->second.mntNsInode = *mntNs;
                    it->second.lowestPid = pid;
                }
            }
        }

        /* The host key is chosen HERE, once, and from the host mode.
         *
         * On a legacy hierarchy the cgroup inode is a perfectly good number
         * that no event ever carries — `bpf_get_current_cgroup_id()` collapses
         * to a constant there — so filing records under it would produce a
         * store that looks healthy, lists containers, and answers every
         * correlation lookup with a miss. The mount-namespace inode is the one
         * an event actually carries. */
        result.keyKind = keyKindFor(m_cgroupMode);

        for (const auto& [mountPath, aggregate] : byMountPath)
        {
            static_cast<void>(mountPath);

            CgroupEntry entry;
            entry.inode = aggregate.inode;
            entry.mntNsInode = aggregate.mntNsInode;

            const auto hostKey = hostKeyOf(entry, result.keyKind);
            if (hostKey == 0)
            {
                continue; // No usable key: unlisted, exactly as before.
            }
            result.allHostKeys.insert(hostKey);

            if (auto match = extractContainerId(aggregate.cgroupPath))
            {
                CgroupEntry containerEntry = entry;
                containerEntry.containerId = std::move(match->containerId);
                containerEntry.hint = match->hint;
                containerEntry.cgroupPath = aggregate.cgroupPath;
                containerEntry.keyController = aggregate.keyController;
                result.containers.push_back(std::move(containerEntry));
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

        if (snapshot.allHostKeys.count(cgroupInode) > 0)
        {
            CgroupEntry hostEntry; // Observed, but not a container: host-process evidence.
            hostEntry.inode = cgroupInode;
            return hostEntry;
        }

        return std::nullopt;
    }

} // namespace wazuh::container_instances
