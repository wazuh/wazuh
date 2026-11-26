// SPDX-License-Identifier: AGPL-3.0-or-later
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <istream>

#include <ext/stdio_filebuf.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <base/logging.hpp>
#include <base/utils/stringUtils.hpp>

#include <conf/fileLoader.hpp>

namespace conf
{

static std::string makeKey(const std::string& high, const std::string& low)
{
    return high + "." + low;
}

static std::string strip_outer_quotes(std::string s)
{
    // Remove surrounding quotes if they are the same type (single or double) and balanced
    if (s.size() >= 2)
    {
        char a = s.front();
        char b = s.back();
        if ((a == '"' && b == '"') || (a == '\'' && b == '\''))
        {
            s.erase(s.begin()); // remove first char
            s.pop_back();       // remove last char
        }
    }
    return s;
}

static OptionMap parseFile(const std::filesystem::path& path, uid_t euid)
{
    OptionMap result;
    // Read as root before the privilege drop, from a directory the service account can write: never follow a link,
    // and accept only a lone regular file that the account cannot have written. A refused file is logged as an error
    // and the engine starts on its defaults: refusing to start would let the account block every restart.
    const int fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0)
    {
        const int err = errno;
        const auto reason = "Cannot open configuration file: " + path.string() + ": " + std::strerror(err);
        if (err == ENOENT)
        {
            throw std::runtime_error(reason);
        }
        LOG_ERROR("{}", reason);
        return result;
    }

    struct stat st {};
    if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_nlink != 1 || (st.st_uid != 0 && st.st_uid != euid)
        || (st.st_mode & (S_IWGRP | S_IWOTH)))
    {
        ::close(fd);
        LOG_ERROR("Ignoring configuration file {}: it must be a lone regular file owned by root, not writable by group "
                  "or others",
                  path.string());
        return result;
    }

    __gnu_cxx::stdio_filebuf<char> fileBuf(fd, std::ios::in); // Owns fd once open, closes it on destruction
    if (!fileBuf.is_open())
    {
        ::close(fd);
        LOG_ERROR("Cannot read configuration file: {}", path.string());
        return result;
    }
    std::istream file(&fileBuf);

    std::string line;
    std::size_t lineNumber {0};
    while (std::getline(file, line))
    {
        ++lineNumber;
        // Trim the line and skip empty lines or full-line comments
        line = base::utils::string::trim(line, " \t\r\n");
        if (line.empty() || line[0] == '#')
            continue;

        // Find positions of '.' and '=' to split into high.key=value
        auto pos_eq = line.find('=');
        auto pos_dot = line.find('.');
        if (pos_eq == std::string::npos || pos_dot == std::string::npos || pos_dot > pos_eq)
        {
            // By number only: the content of a file that is not a configuration file must not reach the log
            LOG_WARNING("Invalid configuration line {} ignored", lineNumber);
            continue;
        }

        std::string high = base::utils::string::trim(line.substr(0, pos_dot), " \t");
        std::string low = base::utils::string::trim(line.substr(pos_dot + 1, pos_eq - pos_dot - 1), " \t");

        // Only parse keys under "analysisd"
        if (high != "analysisd")
            continue;

        // Extract the right-hand side (RHS) after '='
        std::string rhs = line.substr(pos_eq + 1);

        // Split on unescaped '#' (inline comments)
        auto parts = base::utils::string::splitEscaped(rhs, '#', '\\');
        std::string value = parts.empty() ? std::string {} : parts.front();

        // Trim whitespace from the value
        value = base::utils::string::trim(value, " \t\r\n");

        // Unescape sequences like \#, \\, \", \'
        value = base::utils::string::unescapeString(value, '\\', "#\\\"'", /*strictMode=*/false);

        // Remove surrounding quotes if present
        value = strip_outer_quotes(value);

        // Store in the result map
        result[makeKey(high, low)] = value;
    }

    return result;
}

OptionMap FileLoader::load() const
{
    OptionMap config {};

    try
    {
        config = parseFile(m_path, m_euid.value_or(::geteuid()));
    }
    catch (const std::exception& e)
    {
        LOG_WARNING("Failed to load configuration: {}", e.what());
    }

    return config;
}

} // namespace conf
