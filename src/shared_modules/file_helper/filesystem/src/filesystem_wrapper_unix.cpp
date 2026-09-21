#include <filesystem_wrapper.hpp>

#include <sys/file.h>
#include <unistd.h>

#include <chrono>

// LCOV_EXCL_START
namespace file_system
{
    int FileSystemWrapper::open(const char* path, int flags, int mode) const
    {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg)
        return ::open(path, flags, mode);
    }

    int FileSystemWrapper::flock(int fd, int operation) const
    {
        return ::flock(fd, operation);
    }

    int FileSystemWrapper::close(int fd) const
    {
        return ::close(fd);
    }

    std::uintmax_t FileSystemWrapper::file_size(const std::filesystem::path& path) const
    {
        std::error_code ec;
        const auto size { std::filesystem::file_size(path, ec) };
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

        const auto start { std::chrono::steady_clock::now() };
        std::uintmax_t total { 0 };
        std::uintmax_t visited { 0 };

        std::filesystem::recursive_directory_iterator it
        {
            path, std::filesystem::directory_options::skip_permission_denied, ec
        };
        const std::filesystem::recursive_directory_iterator end;

        if (ec)
        {
            return 0;
        }

        while (it != end)
        {
            if (++visited > maxEntries || std::chrono::steady_clock::now() - start > deadline)
            {
                return 0;
            }

            // is_regular_file() follows symlinks, so a link inside the tree would add its
            // target's bytes a second time. Bundles are full of such links (Frameworks keep
            // Versions/Current and a top-level alias per binary), so skip links outright and
            // count only the real files, the way du does.
            if (!it->is_symlink(ec) && !ec && it->is_regular_file(ec) && !ec)
            {
                const auto entrySize { it->file_size(ec) };

                if (ec)
                {
                    return 0;
                }

                total += entrySize;
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
