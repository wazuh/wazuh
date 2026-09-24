#include <filesystem_wrapper.hpp>

// LCOV_EXCL_START
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
        return std::filesystem::is_symlink(path);
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

    std::uintmax_t FileSystemWrapper::directory_size(const std::filesystem::path& path,
                                                     std::uintmax_t maxEntries,
                                                     std::chrono::milliseconds deadline) const
    {
        std::error_code ec;

        if (!std::filesystem::is_directory(path, ec) || ec)
        {
            return 0;
        }

        const auto start = std::chrono::steady_clock::now();

        std::filesystem::recursive_directory_iterator it(
            path, std::filesystem::directory_options::skip_permission_denied, ec);
        const std::filesystem::recursive_directory_iterator end;

        if (ec)
        {
            return 0;
        }

        std::uintmax_t total {0};
        std::uintmax_t entries {0};

        while (it != end)
        {
            if (++entries > maxEntries)
            {
                return 0;
            }

            if (std::chrono::steady_clock::now() - start > deadline)
            {
                return 0;
            }

            // is_symlink() never follows the link, unlike is_regular_file(), which does. Skipping it here
            // is what keeps a file or directory reachable through both its real path and a symlinked alias
            // from being counted twice.
            const bool isSymlink = it->is_symlink(ec);

            if (ec)
            {
                return 0;
            }

            if (!isSymlink)
            {
                const bool isRegularFile = it->is_regular_file(ec);

                if (ec)
                {
                    return 0;
                }

                if (isRegularFile)
                {
                    const auto size = it->file_size(ec);

                    if (ec)
                    {
                        return 0;
                    }

                    total += size;
                }
            }

            it.increment(ec);

            if (ec)
            {
                return 0;
            }
        }

        return total;
    }
} // namespace file_system
// LCOV_EXCL_STOP
