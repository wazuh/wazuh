#include "rootfs_file_walker.hpp"

#include "hash_helper.hpp"

#include <dirent.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#include <cstdio>
#include <deque>

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

} // namespace

bool IsOverlayWhiteout(mode_t mode, dev_t rdev)
{
    return S_ISCHR(mode) && major(rdev) == 0 && minor(rdev) == 0;
}

WalkResult WalkContainerPath(pid_t              pid,
                              const std::string& internal_path,
                              int                recursion_level,
                              size_t             max_files,
                              size_t             max_hash_bytes)
{
    WalkResult result;

    const std::string root_host_path =
        "/proc/" + std::to_string(pid) + "/root" + internal_path;

    struct stat root_st{};
    if (::lstat(root_host_path.c_str(), &root_st) != 0) {
        result.root_missing = true;
        return result;
    }

    std::deque<PendingDir> pending;
    if (S_ISDIR(root_st.st_mode)) {
        pending.push_back({root_host_path, internal_path, recursion_level});
    } else {
        // internal_path itself names a single file, not a directory.
        pending.push_back({root_host_path, internal_path, -1});
    }

    while (!pending.empty()) {
        auto [host_dir, logical_dir, remaining_depth] = std::move(pending.front());
        pending.pop_front();

        struct stat st{};
        if (::lstat(host_dir.c_str(), &st) != 0) continue;

        if (!S_ISDIR(st.st_mode)) {
            // A leaf entry queued directly (the "internal_path is a file" case,
            // or a file discovered while scanning a directory below).
            if (max_files != 0 && result.rows.size() >= max_files) {
                result.truncated = true;
                break;
            }
            if (IsOverlayWhiteout(st.st_mode, st.st_rdev)) continue;
            if (!S_ISREG(st.st_mode) && !S_ISLNK(st.st_mode)) continue; // skip fifo/socket/device

            FileBaselineRow row;
            row.path        = logical_dir;
            row.permissions  = OctalPermissions(st.st_mode);
            row.uid          = std::to_string(st.st_uid);
            row.gid          = std::to_string(st.st_gid);
            row.mtime        = static_cast<int64_t>(st.st_mtime);
            row.size         = static_cast<uint64_t>(st.st_size);
            row.inode        = static_cast<uint64_t>(st.st_ino);
            row.device       = static_cast<uint64_t>(st.st_dev);
            row.is_symlink   = S_ISLNK(st.st_mode);

            if (S_ISREG(st.st_mode)) {
                FileHashes hashes;
                if (HashFile(host_dir, max_hash_bytes, hashes)) {
                    row.hash_md5    = hashes.md5;
                    row.hash_sha1   = hashes.sha1;
                    row.hash_sha256 = hashes.sha256;
                }
            }

            result.rows.push_back(std::move(row));
            continue;
        }

        // Directory: emit no row for the directory itself (matches FIM's
        // file-oriented state model), just recurse into its entries.
        DIR* d = ::opendir(host_dir.c_str());
        if (d == nullptr) continue;

        while (auto* ent = ::readdir(d)) {
            const std::string name = ent->d_name;
            if (name == "." || name == "..") continue;

            const std::string child_host    = host_dir + "/" + name;
            const std::string child_logical =
                (logical_dir == "/") ? ("/" + name) : (logical_dir + "/" + name);

            struct stat child_st{};
            if (::lstat(child_host.c_str(), &child_st) != 0) continue;

            if (S_ISDIR(child_st.st_mode)) {
                if (remaining_depth == 0) continue; // depth exhausted, don't descend further
                const int next_depth = (remaining_depth < 0) ? -1 : (remaining_depth - 1);
                pending.push_back({child_host, child_logical, next_depth});
            } else {
                pending.push_back({child_host, child_logical, 0});
            }
        }
        ::closedir(d);

        if (max_files != 0 && result.rows.size() >= max_files) {
            result.truncated = true;
            break;
        }
    }

    return result;
}

} // namespace wazuh::container_baseline
