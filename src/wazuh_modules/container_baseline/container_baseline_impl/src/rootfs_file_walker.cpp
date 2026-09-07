#include "rootfs_file_walker.hpp"

#include "hash_helper.hpp"
#include "id_map.hpp"
#include "user_scanner.hpp"

#include <dirent.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#include <cerrno>
#include <cstdio>
#include <deque>
#include <unordered_map>

namespace wazuh::container_baseline {

namespace {

std::string OctalPermissions(mode_t mode)
{
    char buf[8];
    std::snprintf(buf, sizeof(buf), "0%o", static_cast<unsigned int>(mode & 07777));
    return buf;
}

// One directory awaiting a walk: its host path, its logical in-container path,
// and how many recursion levels remain (mirrors the caller's recursion_level).
struct PendingDir
{
    std::string host_path;
    std::string logical_path;
    int         remaining_depth; // negative == unlimited
};

/// Decides whether the walk may descend into a directory that lives on a
/// different device than the walk root.
///
/// /proc/<pid>/root is the container's whole mount-namespace view, so following
/// every mount is how a `hostPath: /` volume turns a container FIM baseline
/// into a full host filesystem scan. Crossing is therefore permitted only into
/// a path the container's own OCI mount list declares as a destination — and
/// never into one whose source is the host root, which is the escape itself.
class MountPolicy
{
    public:
        explicit MountPolicy(const ContainerContextPtr& context)
        {
            if (!context) return;

            for (const auto& mount : context->oci_mounts)
            {
                if (mount.destination.empty()) continue;

                // A mount OF the host root is exactly the case this guard
                // exists to stop; never treat it as an allowed destination.
                if (mount.source == "/") continue;

                m_allowed.push_back(mount.destination);
            }
        }

        /// @param logical_path In-container path of the directory being entered.
        [[nodiscard]] bool mayCrossInto(const std::string& logical_path) const
        {
            for (const auto& dest : m_allowed)
            {
                if (IsPathWithinMount(logical_path, dest)) return true;
            }
            return false;
        }

    private:
        std::vector<std::string> m_allowed;
};

/// uid/gid -> name, read from the container's own account files so ownership
/// names are the container's, not the host's. Built once per walk.
struct AccountNames
{
    std::unordered_map<int64_t, std::string> users;
    std::unordered_map<int64_t, std::string> groups;

    static AccountNames ForPid(pid_t pid)
    {
        AccountNames names;
        for (const auto& user : ScanContainerUsers(pid))
        {
            names.users.emplace(user.uid, user.name);
        }
        for (const auto& group : ScanContainerGroups(pid))
        {
            names.groups.emplace(group.gid, group.name);
        }
        return names;
    }

    [[nodiscard]] std::string userName(int64_t uid) const
    {
        const auto it = users.find(uid);
        return (it != users.end()) ? it->second : std::string{};
    }

    [[nodiscard]] std::string groupName(int64_t gid) const
    {
        const auto it = groups.find(gid);
        return (it != groups.end()) ? it->second : std::string{};
    }
};

} // namespace

bool IsOverlayWhiteout(mode_t mode, dev_t rdev)
{
    return S_ISCHR(mode) && major(rdev) == 0 && minor(rdev) == 0;
}

bool IsPathWithinMount(const std::string& logical_path, const std::string& mount_destination)
{
    if (mount_destination.empty()) return false;

    if (logical_path == mount_destination) return true;

    if (logical_path.size() <= mount_destination.size()) return false;
    if (logical_path.compare(0, mount_destination.size(), mount_destination) != 0) return false;

    // The next character must be a separator, or "/variable" would count as
    // being inside "/var". A destination that already ends in '/' has its own
    // separator.
    return mount_destination.back() == '/' || logical_path[mount_destination.size()] == '/';
}

WalkResult WalkContainerPath(pid_t                      pid,
                              const std::string&         internal_path,
                              int                        recursion_level,
                              size_t                     max_files,
                              size_t                     max_hash_bytes,
                              const ContainerContextPtr&   context,
                              const HashSelection&         hashes,
                              const std::function<void()>& rate_limit)
{
    WalkResult result;

    const std::string proc_root = "/proc/" + std::to_string(pid) + "/root";
    const std::string root_host_path = proc_root + internal_path;

    struct stat root_st{};
    if (::lstat(root_host_path.c_str(), &root_st) != 0) {
        const int lookup_errno = errno;

        // "Absent from the image" and "could not look" are different facts, and
        // D17 turns on the difference: only the first may authorise deleting
        // the rows stored under this root.
        //
        // The check that makes the distinction safe is the second lstat.
        // /proc/<pid>/root/<path> also fails with ENOENT once the pid has
        // exited, so errno alone would report a whole vanished container as a
        // set of vanished directories — C15's mass false delete arriving one
        // root at a time. If the rootfs is no longer addressable, nothing is
        // known about this root.
        struct stat rootfs_st{};
        const bool rootfs_addressable = ::lstat(proc_root.c_str(), &rootfs_st) == 0;

        if ((lookup_errno == ENOENT || lookup_errno == ENOTDIR) && rootfs_addressable) {
            result.root_missing = true;
        } else {
            result.root_unreadable = true;
        }

        return result;
    }

    const MountPolicy mount_policy{context};
    const auto        uid_map = IdMap::FromProc(pid, "uid_map");
    const auto        gid_map = IdMap::FromProc(pid, "gid_map");
    const auto        names   = AccountNames::ForPid(pid);
    const dev_t       root_dev = root_st.st_dev;

    // Emits one row for an already-stat'ed leaf entry. Returns false when the
    // row cap has been reached, so the caller can stop the whole walk.
    const auto emitLeaf = [&](const std::string& host_path,
                              const std::string& logical_path,
                              const struct stat& st) -> bool {
        if (max_files != 0 && result.rows.size() >= max_files) {
            result.truncated = true;
            return false;
        }

        if (!S_ISREG(st.st_mode) && !S_ISLNK(st.st_mode)) return true; // skip fifo/socket/device

        // Throttle before doing the expensive part. FIM's check_max_fps() is a
        // process-global token bucket, so this shares one files-per-second
        // budget with the host walk rather than competing with it.
        if (rate_limit) rate_limit();

        FileBaselineRow row;
        row.path        = logical_path;
        row.permissions = OctalPermissions(st.st_mode);

        const auto container_uid = static_cast<int64_t>(uid_map.toContainer(st.st_uid));
        const auto container_gid = static_cast<int64_t>(gid_map.toContainer(st.st_gid));
        row.uid   = std::to_string(container_uid);
        row.gid   = std::to_string(container_gid);
        row.owner = names.userName(container_uid);
        row.group = names.groupName(container_gid);

        row.mtime      = static_cast<int64_t>(st.st_mtime);
        row.size       = static_cast<uint64_t>(st.st_size);
        row.inode      = static_cast<uint64_t>(st.st_ino);
        row.device     = static_cast<uint64_t>(st.st_dev);
        row.is_symlink = S_ISLNK(st.st_mode);

        // Files over the cap are NOT hashed and their hash fields stay empty —
        // the same policy host FIM applies via syscheck.file_max_size. Hashing
        // only a prefix would produce a digest that matches no other reader and
        // that collides across any two files sharing that prefix, which in a
        // file-integrity feature is worse than reporting no hash at all.
        if (S_ISREG(st.st_mode) && hashes.any() &&
            (max_hash_bytes == 0 || static_cast<size_t>(st.st_size) <= max_hash_bytes)) {
            FileHashes digests;
            if (HashFile(host_path, digests, hashes)) {
                row.hash_md5    = digests.md5;
                row.hash_sha1   = digests.sha1;
                row.hash_sha256 = digests.sha256;
            }
        }

        result.rows.push_back(std::move(row));
        return true;
    };

    if (!S_ISDIR(root_st.st_mode)) {
        // internal_path itself names a single file, not a directory.
        emitLeaf(root_host_path, internal_path, root_st);
        return result;
    }

    std::deque<PendingDir> pending;
    pending.push_back({root_host_path, internal_path, recursion_level});

    while (!pending.empty()) {
        auto [host_dir, logical_dir, remaining_depth] = std::move(pending.front());
        pending.pop_front();

        DIR* d = ::opendir(host_dir.c_str());
        if (d == nullptr) continue;

        bool cap_reached = false;

        while (auto* ent = ::readdir(d)) {
            const std::string name = ent->d_name;
            if (name == "." || name == "..") continue;

            const std::string child_host    = host_dir + "/" + name;
            const std::string child_logical =
                (logical_dir == "/") ? ("/" + name) : (logical_dir + "/" + name);

            // One lstat per entry. The previous implementation stat'ed each
            // entry here AND again after popping it off the queue, doubling the
            // syscall count for the whole tree.
            struct stat child_st{};
            if (::lstat(child_host.c_str(), &child_st) != 0) continue;

            if (S_ISDIR(child_st.st_mode)) {
                if (remaining_depth == 0) continue; // depth exhausted, don't descend further

                // Mount boundary: only descend onto another device when the
                // container itself declares that path as a mount destination.
                if (child_st.st_dev != root_dev && !mount_policy.mayCrossInto(child_logical)) {
                    continue;
                }

                const int next_depth = (remaining_depth < 0) ? -1 : (remaining_depth - 1);
                pending.push_back({child_host, child_logical, next_depth});
                continue;
            }

            if (!emitLeaf(child_host, child_logical, child_st)) {
                cap_reached = true;
                break;
            }
        }

        ::closedir(d);

        if (cap_reached) break;
    }

    return result;
}

} // namespace wazuh::container_baseline
