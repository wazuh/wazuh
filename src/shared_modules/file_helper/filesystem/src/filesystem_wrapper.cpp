#include <filesystem_wrapper.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

// LCOV_EXCL_START
namespace
{
    // MinGW's std::filesystem reports symbolic links and junctions as plain files and directories,
    // so on Windows they are recognized by their reparse tag. Other reparse points (cloud
    // placeholders, deduplicated files) are regular data and are not treated as links.
    bool isLink(const std::filesystem::path& path)
    {
#ifdef _WIN32
        const auto wide {path.wstring()};
        const auto attributes {GetFileAttributesW(wide.c_str())};

        // Cheap filter first: only a reparse point can be a link, and few entries are one
        if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_REPARSE_POINT))
        {
            return false;
        }

        WIN32_FIND_DATAW data {};
        const auto handle {FindFirstFileW(wide.c_str(), &data)};

        if (handle != INVALID_HANDLE_VALUE)
        {
            FindClose(handle);

            if ((data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) &&
                    (data.dwReserved0 == IO_REPARSE_TAG_SYMLINK || data.dwReserved0 == IO_REPARSE_TAG_MOUNT_POINT))
            {
                return true;
            }
        }

#endif
        std::error_code ec;
        return std::filesystem::is_symlink(std::filesystem::symlink_status(path, ec));
    }
} // namespace

namespace file_system
{
    bool FileSystemWrapper::exists(const std::filesystem::path& path) const
    {
        return std::filesystem::exists(path);
    }

    bool FileSystemWrapper::is_directory(const std::filesystem::path& path) const
    {
        return std::filesystem::is_directory(path);
    }

    bool FileSystemWrapper::is_regular_file(const std::filesystem::path& path) const
    {
        return std::filesystem::is_regular_file(path);
    }

    bool FileSystemWrapper::is_socket(const std::filesystem::path& path) const
    {
        return std::filesystem::is_socket(path);
    }

    bool FileSystemWrapper::is_symlink(const std::filesystem::path& path) const
    {
#ifdef _WIN32
        return isLink(path) || std::filesystem::is_symlink(path);
#else
        return std::filesystem::is_symlink(path);
#endif
    }

    bool FileSystemWrapper::is_absolute(const std::filesystem::path& path) const
    {
        return path.is_absolute();
    }

    std::filesystem::path FileSystemWrapper::canonical(const std::filesystem::path& path) const
    {
        return std::filesystem::canonical(path);
    }

    std::uintmax_t FileSystemWrapper::remove_all(const std::filesystem::path& path) const
    {
        return std::filesystem::remove_all(path);
    }

    std::filesystem::path FileSystemWrapper::temp_directory_path() const
    {
        return std::filesystem::temp_directory_path();
    }

    bool FileSystemWrapper::create_directories(const std::filesystem::path& path) const
    {
        return std::filesystem::create_directories(path);
    }

    std::vector<std::filesystem::path> FileSystemWrapper::list_directory(const std::filesystem::path& path) const
    {
        std::vector<std::filesystem::path> result;

        for (const auto& entry : std::filesystem::directory_iterator(path))
        {
            result.push_back(entry.path());
        }

        return result;
    }

    void FileSystemWrapper::rename(const std::filesystem::path& from, const std::filesystem::path& to) const
    {
        std::filesystem::rename(from, to);
    }

    bool FileSystemWrapper::remove(const std::filesystem::path& path) const
    {
        return std::filesystem::remove(path);
    }

    std::uintmax_t FileSystemWrapper::file_size(const std::filesystem::path& path) const
    {
        std::error_code ec;

        if (!std::filesystem::is_regular_file(path, ec) || ec)
        {
            return 0;
        }

        const auto size = std::filesystem::file_size(path, ec);
        return ec ? 0 : size;
    }

    std::optional<std::uintmax_t> FileSystemWrapper::directory_size(const std::filesystem::path& path,
                                                                    std::uintmax_t maxEntries,
                                                                    std::chrono::milliseconds deadline) const
    {
        std::error_code ec;

        // A linked root points at a tree that is not this one, so its size is not established. Checked
        // first: is_directory() follows the link and would reach its target.
        if (isLink(path) || !std::filesystem::is_directory(path, ec) || ec)
        {
            return std::nullopt;
        }

        const auto start = std::chrono::steady_clock::now();

        std::filesystem::recursive_directory_iterator it(
            path, std::filesystem::directory_options::skip_permission_denied, ec);
        const std::filesystem::recursive_directory_iterator end;

        if (ec)
        {
            return std::nullopt;
        }

        std::uintmax_t total {0};
        std::uintmax_t entries {0};

        while (it != end)
        {
            if (++entries > maxEntries)
            {
                return std::nullopt;
            }

            if (std::chrono::steady_clock::now() - start > deadline)
            {
                return std::nullopt;
            }

            // is_symlink() never follows the link, unlike is_regular_file(), which does. Skipping it here
            // is what keeps a file or directory reachable through both its real path and a symlinked alias
            // from being counted twice.
            bool isSymlink = it->is_symlink(ec);

            if (ec)
            {
                return std::nullopt;
            }

#ifdef _WIN32
            isSymlink = isSymlink || isLink(it->path());
#endif

            if (isSymlink)
            {
                // Without this, a junction reported as a directory would be descended into
                it.disable_recursion_pending();
            }
            else
            {
                const bool isRegularFile = it->is_regular_file(ec);

                if (ec)
                {
                    return std::nullopt;
                }

                if (isRegularFile)
                {
                    const auto size = it->file_size(ec);

                    if (ec)
                    {
                        return std::nullopt;
                    }

                    total += size;
                }
            }

            it.increment(ec);

            if (ec)
            {
                return std::nullopt;
            }
        }

        return total;
    }
} // namespace file_system
// LCOV_EXCL_STOP
