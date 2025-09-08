#include <filesystem_wrapper.hpp>

namespace file_system
{
    int
    FileSystemWrapper::open([[maybe_unused]] const char*, [[maybe_unused]] int flags, [[maybe_unused]] int mode) const
    {
        return 0;
    }

    int FileSystemWrapper::flock([[maybe_unused]] int fd, [[maybe_unused]] int operation) const
    {
        return 0;
    }

    int FileSystemWrapper::close([[maybe_unused]] int fd) const
    {
        return 0;
    }
} // namespace file_system
