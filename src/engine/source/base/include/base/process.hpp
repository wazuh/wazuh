#ifndef _BASE_PROCESS_HPP
#define _BASE_PROCESS_HPP

#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <sys/stat.h>
#include <unistd.h>

#include <fmt/format.h>

#include <base/error.hpp>

namespace base::process
{
/**
 * @brief Transforms the current process into a daemon (double fork + detach).
 */
void goDaemon()
{
    pid_t pid = fork();
    if (pid < 0)
    {
        throw std::runtime_error {fmt::format("FORK_ERROR (1st): {} ({})", std::strerror(errno), errno)};
    }
    if (pid > 0)
    {
        exit(EXIT_SUCCESS); // Parent exits
    }

    if (setsid() < 0)
    {
        throw std::runtime_error {fmt::format("SETSID_ERROR: {} ({})", std::strerror(errno), errno)};
    }

    pid = fork();
    if (pid < 0)
    {
        throw std::runtime_error {fmt::format("FORK_ERROR (2nd): {} ({})", std::strerror(errno), errno)};
    }
    if (pid > 0)
    {
        exit(EXIT_SUCCESS); // First child exits
    }

    // Optional: set file mode creation mask
    umask(027);

    // Redirect stdin, stdout, stderr to /dev/null
    int fd = open("/dev/null", O_RDWR);
    if (fd < 0)
    {
        throw std::runtime_error {
            fmt::format("REDIRECT_ERROR: Could not open /dev/null - {} ({})", std::strerror(errno), errno)};
    }

    dup2(fd, STDIN_FILENO);
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    close(fd);
}

/**
 * @brief Creates a PID file for the specified service name.
 *
 * @param path Directory where the PID file will be written.
 * @param name Service name (used in filename).
 * @param pid Process ID to write.
 * @return std::nullopt if successful, otherwise a base::Error describing the issue.
 */
OptError createPID(const std::string& path, const std::string& name, int pid)
{
    const auto file = std::filesystem::path(path) / fmt::format("{}-{}.pid", name, pid);

    std::ofstream ofs(file, std::ios::trunc);
    if (!ofs)
    {
        return Error {fmt::format("FILE_ERROR: {} - {} ({})", file.string(), std::strerror(errno), errno)};
    }

    ofs << pid << '\n';
    ofs.close();

    if (chmod(file.c_str(), 0640) != 0)
    {
        return Error {fmt::format("CHMOD_ERROR: {} - {} ({})", file.string(), std::strerror(errno), errno)};
    }

    return std::nullopt;
}

} // namespace base::process

#endif // _BASE_PROCESS_HPP
