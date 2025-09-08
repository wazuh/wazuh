#include <filesystem_wrapper.hpp>

#include <sys/file.h>
#include <unistd.h>

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
} // namespace file_system
