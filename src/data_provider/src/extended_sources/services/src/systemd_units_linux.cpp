/* Copyright (C) Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <pwd.h>
#include <unistd.h>
#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <functional>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <sstream>
#include <stdexcept>
#include "dbus_wrapper.hpp"
#include "systemd_units_linux.hpp"
#include "stringHelper.h"

namespace
{
    /// @brief Owns a private D-Bus connection for the duration of a scope.
    ///
    /// bus_get_private() transfers ownership to the caller, so the connection has to be closed
    /// and unreferenced on every exit path. Doing that through a guard rather than by hand
    /// keeps a future early return from reintroducing the leak.
    class ScopedDBusConnection final
    {
        public:
            ScopedDBusConnection(std::shared_ptr<IDBusWrapper> dbusWrapper, DBusConnection* connection)
                : m_dbusWrapper(std::move(dbusWrapper))
                , m_connection(connection)
            {
            }

            ~ScopedDBusConnection()
            {
                if (m_connection)
                {
                    m_dbusWrapper->connection_close(m_connection);
                    m_dbusWrapper->connection_unref(m_connection);
                }
            }

            ScopedDBusConnection(const ScopedDBusConnection&) = delete;
            ScopedDBusConnection& operator=(const ScopedDBusConnection&) = delete;

            /// @brief Returns the owned connection, or nullptr if it could not be acquired.
            DBusConnection* get() const
            {
                return m_connection;
            }

        private:
            std::shared_ptr<IDBusWrapper> m_dbusWrapper;
            DBusConnection* m_connection;
    };

    constexpr auto SERVICE_SUFFIX {".service"};

    // Unit files are root-owned, but bound the read anyway.
    constexpr size_t MAX_UNIT_FILE_BYTES {1024 * 1024};

    // System unit search paths, highest priority first (systemd.unit(5)).
    const std::vector<std::string> DEFAULT_UNIT_SEARCH_PATHS
    {
        "/etc/systemd/system.control", "/run/systemd/system.control", "/run/systemd/transient",
        "/run/systemd/generator.early", "/etc/systemd/system", "/etc/systemd/system.attached",
        "/run/systemd/system", "/run/systemd/system.attached", "/run/systemd/generator",
        "/usr/local/lib/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system",
        "/run/systemd/generator.late"
    };

    std::string trim(const std::string& value)
    {
        const auto first = value.find_first_not_of(" \t\r");

        if (first == std::string::npos)
        {
            return {};
        }

        const auto last = value.find_last_not_of(" \t\r");
        return value.substr(first, last - first + 1);
    }

    void parseUnitLine(const std::string& line,
                       std::string& section,
                       UnitFileValues& values,
                       const std::function<bool(std::string&)>& expand)
    {
        if (line.empty())
        {
            return;
        }

        if (line[0] == '[')
        {
            section = line;
            return;
        }

        const auto separator = line.find('=');

        if (separator == std::string::npos)
        {
            return;
        }

        const auto key = trim(line.substr(0, separator));
        auto value = trim(line.substr(separator + 1));
        const bool relevant = (section == "[Unit]" && (key == "Description" || key == "SourcePath")) ||
                              (section == "[Service]" && key == "User");

        // systemd ignores an assignment whose specifiers it cannot resolve.
        if (!relevant || (expand && !expand(value)))
        {
            return;
        }

        if (section == "[Unit]" && key == "Description")
        {
            values.description = std::move(value);
        }
        else if (section == "[Unit]" && key == "SourcePath")
        {
            values.sourcePath = std::move(value);
        }
        else if (section == "[Service]" && key == "User")
        {
            values.user = std::move(value);
        }
    }

    // systemd releases that added drop-in directories beyond "<unit>.d".
    constexpr unsigned int PREFIX_DROP_INS_VERSION {239};
    constexpr unsigned int TOP_LEVEL_DROP_INS_VERSION {244};
    constexpr unsigned int UNKNOWN_SPECIFIER_REJECTED_VERSION {236};

    // An unknown version (0) is taken as a current one.
    bool supportedSince(unsigned int systemdVersion, unsigned int since)
    {
        return systemdVersion == 0 || systemdVersion >= since;
    }

    SystemdUnitsSettings defaultSettings()
    {
        static const auto consecutiveFailures {std::make_shared<std::atomic<unsigned int>>(0)};
        return {DEFAULT_UNIT_SEARCH_PATHS, "/run/systemd/system", consecutiveFailures};
    }

    // Unit name an alias symlink points to, or empty if the path is not an alias. Older
    // systemd lists aliases with their target's state instead of "alias".
    std::string aliasTarget(const std::filesystem::path& path)
    {
        std::error_code ec;

        if (!std::filesystem::is_symlink(path, ec))
        {
            return {};
        }

        const auto target = std::filesystem::read_symlink(path, ec);

        if (ec || target == "/dev/null" || target.filename() == path.filename())
        {
            return {};
        }

        return target.filename().string();
    }

    enum class ReadResult
    {
        Read,
        Missing,
        Unreadable
    };

    // Reads up to MAX_UNIT_FILE_BYTES of a regular file. The type is checked on the opened
    // descriptor, so a FIFO or device (a masked unit's /dev/null) is never read.
    ReadResult readRegularFile(const std::string& path, std::string& content)
    {
        content.clear();
        const int fd = ::open(path.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);

        if (fd < 0)
        {
            return errno == ENOENT ? ReadResult::Missing : ReadResult::Unreadable;
        }

        struct stat fileStat {};

        bool success = ::fstat(fd, &fileStat) == 0 && S_ISREG(fileStat.st_mode);

        while (success && content.size() < MAX_UNIT_FILE_BYTES)
        {
            char buffer[4096];
            const auto toRead = std::min(sizeof(buffer), MAX_UNIT_FILE_BYTES - content.size());
            const auto bytes = ::read(fd, buffer, toRead);

            if (bytes > 0)
            {
                content.append(buffer, static_cast<size_t>(bytes));
            }
            else if (bytes == 0)
            {
                break;
            }
            else if (errno != EINTR)
            {
                success = false;
            }
        }

        ::close(fd);
        return success ? ReadResult::Read : ReadResult::Unreadable;
    }

    // Prefix of a unit name: the part before "@" for templates and instances, else the name
    // without ".service".
    std::string unitPrefix(const std::string& unitName)
    {
        const auto at = unitName.find('@');
        return at != std::string::npos ? unitName.substr(0, at)
               : unitName.substr(0, unitName.size() - std::strlen(SERVICE_SUFFIX));
    }

    // Instance of a unit name ("tty1" for "getty@tty1.service"), empty for other names.
    std::string unitInstance(const std::string& unitName)
    {
        const auto at = unitName.find('@');

        if (at == std::string::npos || !Utils::endsWith(unitName, SERVICE_SUFFIX))
        {
            return {};
        }

        return unitName.substr(at + 1, unitName.size() - at - 1 - std::strlen(SERVICE_SUFFIX));
    }

    // Drop-in directories of one unit name in one search path, as systemd's
    // unit_file_find_dirs(): "<name>.d", then the template's for an instance, then the same for
    // the name's dash prefix ("a-b-c.service" -> "a-b-.service" -> "a-.service").
    void nameDropInDirs(const std::filesystem::path& searchPath,
                        const std::string& unitName,
                        bool withPrefixes,
                        std::vector<std::filesystem::path>& dirs)
    {
        dirs.push_back(searchPath / (unitName + ".d"));

        const auto instance = unitInstance(unitName);

        if (!instance.empty())
        {
            nameDropInDirs(searchPath, unitPrefix(unitName) + "@" + SERVICE_SUFFIX, withPrefixes, dirs);
        }

        if (!withPrefixes)
        {
            return;
        }

        auto prefix = unitPrefix(unitName);
        bool chopped {false};

        for (;;)
        {
            const auto dash = prefix.rfind('-');

            if (dash == std::string::npos || dash == 0)
            {
                return;
            }

            // A trailing dash is chopped once and the search goes on.
            if (dash + 1 < prefix.size() || chopped)
            {
                prefix.resize(dash + 1);
                break;
            }

            prefix.resize(dash);
            chopped = true;
        }

        nameDropInDirs(searchPath, prefix + (instance.empty() ? "" : "@" + instance) + SERVICE_SUFFIX, withPrefixes, dirs);
    }

    // Drop-in directories in systemd's order (unit_file_find_dropin_paths()): the unit's own
    // directories in every search path, then the same for each alias, then "service.d" in
    // every search path.
    std::vector<std::filesystem::path> dropInDirs(const std::string& unitName,
                                                  const std::vector<std::string>& aliases,
                                                  const std::vector<std::string>& searchPaths,
                                                  unsigned int systemdVersion)
    {
        std::vector<std::filesystem::path> dirs;
        std::vector<std::string> names {unitName};
        names.insert(names.end(), aliases.begin(), aliases.end());
        const bool withPrefixes = supportedSince(systemdVersion, PREFIX_DROP_INS_VERSION);

        for (const auto& name : names)
        {
            for (const auto& searchPath : searchPaths)
            {
                nameDropInDirs(searchPath, name, withPrefixes, dirs);
            }
        }

        if (supportedSince(systemdVersion, TOP_LEVEL_DROP_INS_VERSION))
        {
            for (const auto& searchPath : searchPaths)
            {
                dirs.push_back(std::filesystem::path(searchPath) / "service.d");
            }
        }

        return dirs;
    }

    // systemd's unit_name_unescape(): "-" is "/" and "\xNN" is the byte NN. A NUL byte makes
    // the text invalid, as in systemd.
    std::optional<std::string> unescapeUnitText(const std::string& text)
    {
        std::string result;

        for (size_t i = 0; i < text.size(); ++i)
        {
            if (text[i] == '-')
            {
                result += '/';
            }
            else if (text[i] == '\\' && i + 3 < text.size() && text[i + 1] == 'x' &&
                     std::isxdigit(static_cast<unsigned char>(text[i + 2])) &&
                     std::isxdigit(static_cast<unsigned char>(text[i + 3])))
            {
                const auto byte = static_cast<char>(std::stoi(text.substr(i + 2, 2), nullptr, 16));

                if (byte == '\0')
                {
                    return std::nullopt;
                }

                result += byte;
                i += 3;
            }
            else
            {
                result += text[i];
            }
        }

        return result;
    }

    // systemd's unit_name_path_unescape() for %f: "-" alone is "/", otherwise the unescaped
    // text as an absolute path, with repeated and trailing slashes removed.
    std::optional<std::string> unescapeUnitPath(const std::string& text)
    {
        if (text.empty() || text == "-")
        {
            return std::string {"/"};
        }

        const auto unescaped = unescapeUnitText(text);

        if (!unescaped)
        {
            return std::nullopt;
        }

        std::string path {"/"};

        for (const auto c : *unescaped)
        {
            if (c != '/' || path.back() != '/')
            {
                path += c;
            }
        }

        if (path.size() > 1 && path.back() == '/')
        {
            path.pop_back();
        }

        return path;
    }

    std::string readFirstLine(const std::string& path)
    {
        std::ifstream file(path);
        std::string line;
        std::getline(file, line);
        return trim(line);
    }

    // KEY=value files such as os-release and machine-info, with optional quotes.
    std::map<std::string, std::string> readKeyValueFile(const std::string& path)
    {
        std::map<std::string, std::string> values;
        std::ifstream file(path);
        std::string line;

        while (std::getline(file, line))
        {
            const auto separator = line.find('=');

            if (separator == std::string::npos || line[0] == '#')
            {
                continue;
            }

            auto value = trim(line.substr(separator + 1));

            if (value.size() >= 2 && (value.front() == '"' || value.front() == '\'') && value.back() == value.front())
            {
                value = value.substr(1, value.size() - 2);
            }

            values[trim(line.substr(0, separator))] = value;
        }

        return values;
    }

    // systemd's architecture names (%a) for the kernel's machine names.
    std::string architectureName(const std::string& machine)
    {
        static const std::map<std::string, std::string> NAMES
        {
            {"x86_64", "x86-64"}, {"i386", "x86"}, {"i486", "x86"}, {"i586", "x86"}, {"i686", "x86"},
            {"aarch64", "arm64"}, {"aarch64_be", "arm64-be"}, {"armv7l", "arm"}, {"armv6l", "arm"},
            {"ppc64le", "ppc64-le"}, {"ppc64", "ppc64"}, {"s390x", "s390x"}, {"riscv64", "riscv64"},
            {"loongarch64", "loongarch64"}
        };
        const auto it = NAMES.find(machine);
        return it != NAMES.end() ? it->second : machine;
    }

    // Host values used by specifiers, read once per collection.
    struct HostFacts
    {
        std::string hostName;
        std::string prettyHostName;
        std::string machineId;
        std::string bootId;
        std::string kernelRelease;
        std::string architecture;
        std::string rootShell;
        std::map<std::string, std::string> osRelease;
    };

    HostFacts readHostFacts()
    {
        HostFacts facts;
        char name[256] {};

        if (::gethostname(name, sizeof(name) - 1) == 0)
        {
            facts.hostName = name;
        }

        facts.prettyHostName = readKeyValueFile("/etc/machine-info")["PRETTY_HOSTNAME"];
        facts.machineId = readFirstLine("/etc/machine-id");
        facts.bootId = readFirstLine("/proc/sys/kernel/random/boot_id");
        facts.bootId.erase(std::remove(facts.bootId.begin(), facts.bootId.end(), '-'), facts.bootId.end());

        struct utsname uts {};

        if (::uname(&uts) == 0)
        {
            facts.kernelRelease = uts.release;
            facts.architecture = architectureName(uts.machine);
        }

        struct passwd pwd {};

        struct passwd* result
        {
            nullptr
        };

        std::vector<char> buffer(16384);

        facts.rootShell = ::getpwuid_r(0, &pwd, buffer.data(), buffer.size(), &result) == 0 && result && pwd.pw_shell ?
                          pwd.pw_shell : "/bin/sh";

        facts.osRelease = readKeyValueFile("/etc/os-release");

        if (facts.osRelease.empty())
        {
            facts.osRelease = readKeyValueFile("/usr/lib/os-release");
        }

        return facts;
    }

    // What a specifier resolves to for a unit, as the system manager resolves it
    // (systemd.unit(5), checked against systemd 259). nullopt: not a specifier systemd knows.
    std::optional<std::string> resolveSpecifier(char specifier,
                                                const std::string& unitName,
                                                const std::string& fragmentPath,
                                                unsigned int systemdVersion,
                                                const HostFacts& facts)
    {
        const auto prefix = unitPrefix(unitName);
        const auto instance = unitInstance(unitName);
        const auto dash = prefix.rfind('-');
        const auto lastComponent = dash == std::string::npos ? prefix : prefix.substr(dash + 1);
        const auto osValue = [&facts](const char* key)
        {
            const auto it = facts.osRelease.find(key);
            return it != facts.osRelease.end() ? it->second : std::string {};
        };

        switch (specifier)
        {
            case '%':
                return std::string {"%"};
            case 'n':
                return unitName;

            case 'N':
                return unitName.substr(0, unitName.size() - std::strlen(SERVICE_SUFFIX));

            case 'p':
                return prefix;

            case 'P':
                return unescapeUnitText(prefix);

            case 'i':
                return instance;

            case 'I':
                return unescapeUnitText(instance);

            case 'f':
                return unescapeUnitPath(instance.empty() ? prefix : instance);

            case 'y':
            case 'Y':
                {
                    std::error_code ec;
                    auto realPath = std::filesystem::canonical(fragmentPath, ec);
                    realPath = ec ? std::filesystem::path(fragmentPath) : realPath;
                    return specifier == 'y' ? realPath.string() : realPath.parent_path().string();
                }

            case 'C':
                return std::string {"/var/cache"};
            case 'd':
                return "/run/credentials/" + unitName;

            case 'D':
                return std::string {"/usr/share"};
            case 'E':
                return std::string {"/etc"};
            case 'L':
                return std::string {"/var/log"};
            case 'S':
                return std::string {"/var/lib"};
            case 't':
                return std::string {"/run"};
            case 'T':
                return std::string {"/tmp"};
            case 'V':
                return std::string {"/var/tmp"};
            case 'h':
                return std::string {"/root"};
            case 's':
                return facts.rootShell;

            case 'u':
                return std::string {"root"};
            case 'U':
                return std::string {"0"};
            case 'g':
                return std::string {"root"};
            case 'G':
                return std::string {"0"};
            case 'H':
                return facts.hostName;

            case 'l':
                return facts.hostName.substr(0, facts.hostName.find('.'));

            case 'q':
                return facts.prettyHostName.empty() ? facts.hostName : facts.prettyHostName;

            case 'm':
                return facts.machineId;

            case 'b':
                return facts.bootId;

            case 'v':
                return facts.kernelRelease;

            case 'a':
                return facts.architecture;

            case 'o':
                return osValue("ID");

            case 'w':
                return osValue("VERSION_ID");

            case 'B':
                return osValue("BUILD_ID");

            case 'W':
                return osValue("VARIANT_ID");

            case 'M':
                return osValue("IMAGE_ID");

            case 'A':
                return osValue("IMAGE_VERSION");

            // Added with prefix drop-ins.
            case 'j':
            case 'J':
                if (!supportedSince(systemdVersion, PREFIX_DROP_INS_VERSION))
                {
                    return std::nullopt;
                }

                return specifier == 'j' ? std::optional<std::string> {lastComponent} :
                       unescapeUnitText(lastComponent);

            // Deprecated cgroup specifiers: valid, but their values need the running manager.
            case 'c':
            case 'r':
            case 'R':
                return std::string {"%"} + specifier;

            default:
                return std::nullopt;
        }
    }

    // Expands the specifiers in a value. Returns false if systemd would reject the value, so
    // the assignment is ignored; systemd 236 and later reject unknown specifiers, older ones
    // keep them literal.
    bool expandSpecifiers(std::string& value,
                          const std::string& unitName,
                          const std::string& fragmentPath,
                          unsigned int systemdVersion,
                          const HostFacts& facts)
    {
        if (value.find('%') == std::string::npos)
        {
            return true;
        }

        const bool rejectsUnknown = supportedSince(systemdVersion, UNKNOWN_SPECIFIER_REJECTED_VERSION);
        std::string result;

        for (size_t i = 0; i < value.size(); ++i)
        {
            if (value[i] != '%')
            {
                result += value[i];
                continue;
            }

            if (i + 1 == value.size())
            {
                if (rejectsUnknown)
                {
                    return false;
                }

                result += '%';
                continue;
            }

            const auto resolved = resolveSpecifier(value[++i], unitName, fragmentPath, systemdVersion, facts);

            if (resolved)
            {
                result += *resolved;
            }
            else if (rejectsUnknown)
            {
                return false;
            }
            else
            {
                result += '%';
                result += value[i];
            }
        }

        value = std::move(result);
        return true;
    }

    // Drop-in files in the order systemd applies them: sorted by file name, a name in an
    // earlier directory hiding the same name in later ones.
    std::vector<std::string> dropInFiles(const std::vector<std::filesystem::path>& dirs)
    {
        std::map<std::string, std::string> filesByName;

        for (const auto& dir : dirs)
        {
            std::error_code ec;
            std::filesystem::directory_iterator it(dir, ec);

            for (; !ec && it != std::filesystem::directory_iterator(); it.increment(ec))
            {
                if (it->path().extension() == ".conf")
                {
                    filesByName.emplace(it->path().filename().string(), it->path().string());
                }
            }
        }

        std::vector<std::string> files;

        for (auto& entry : filesByName)
        {
            files.push_back(std::move(entry.second));
        }

        return files;
    }

    // Values of an unloaded unit: its fragment, then its drop-ins, with the specifiers systemd
    // would expand when loading it.
    ReadResult readUnitFileValues(const std::string& fragmentPath,
                                  const std::string& unitName,
                                  const std::vector<std::filesystem::path>& dropInDirectories,
                                  unsigned int systemdVersion,
                                  const HostFacts& facts,
                                  UnitFileValues& values)
    {
        std::string content;
        const auto result = readRegularFile(fragmentPath, content);

        if (result != ReadResult::Read)
        {
            return result;
        }

        const std::function<bool(std::string&)> expand = [&](std::string & value)
        {
            return expandSpecifiers(value, unitName, fragmentPath, systemdVersion, facts);
        };

        std::istringstream fragment {content};
        values = SystemdUnitsProvider::parseUnitFile(fragment, std::move(values), expand);

        for (const auto& dropInPath : dropInFiles(dropInDirectories))
        {
            if (readRegularFile(dropInPath, content) == ReadResult::Read)
            {
                std::istringstream dropIn {content};
                values = SystemdUnitsProvider::parseUnitFile(dropIn, std::move(values), expand);
            }
        }

        return result;
    }

    // Enabled template instances ("getty@tty1.service"): links in the search paths' .wants,
    // .requires and .upholds directories. ListUnitFiles lists only their template. The first
    // link found for a name wins, as the search paths go from highest priority.
    std::vector<std::pair<std::string, std::string>> enabledInstances(const std::vector<std::string>& searchPaths)
    {
        std::vector<std::pair<std::string, std::string>> instances;
        std::unordered_set<std::string> seen;

        for (const auto& searchPath : searchPaths)
        {
            std::error_code ec;
            std::filesystem::directory_iterator dirIt(searchPath, ec);

            for (; !ec && dirIt != std::filesystem::directory_iterator(); dirIt.increment(ec))
            {
                const auto dirName = dirIt->path().filename().string();

                if (!Utils::endsWith(dirName, ".wants") && !Utils::endsWith(dirName, ".requires") &&
                        !Utils::endsWith(dirName, ".upholds"))
                {
                    continue;
                }

                std::error_code linkEc;
                std::filesystem::directory_iterator linkIt(dirIt->path(), linkEc);

                for (; !linkEc && linkIt != std::filesystem::directory_iterator(); linkIt.increment(linkEc))
                {
                    const auto name = linkIt->path().filename().string();

                    if (!unitInstance(name).empty() && seen.insert(name).second)
                    {
                        instances.emplace_back(name, linkIt->path().string());
                    }
                }
            }
        }

        return instances;
    }
}

UnitFileValues SystemdUnitsProvider::parseUnitFile(std::istream& input,
                                                   UnitFileValues values,
                                                   const std::function<bool(std::string&)>& expand)
{
    std::string section;
    std::string rawLine;
    std::string pending;
    bool continued {false};

    while (std::getline(input, rawLine))
    {
        auto part = trim(rawLine);

        // Comments are ignored, also between continued lines.
        if (!part.empty() && (part[0] == '#' || part[0] == ';'))
        {
            continue;
        }

        // A trailing backslash joins the next line, the backslash becoming a space.
        if (!part.empty() && part.back() == '\\')
        {
            part.back() = ' ';
            pending += part;
            continued = true;
            continue;
        }

        parseUnitLine(continued ? pending + part : part, section, values, expand);
        pending.clear();
        continued = false;
    }

    if (continued)
    {
        parseUnitLine(pending, section, values, expand);
    }

    return values;
}

std::string SystemdUnitsProvider::instanceLinkState(const std::string& linkPath)
{
    if (Utils::startsWith(linkPath, "/etc/"))
    {
        return "enabled";
    }

    return Utils::startsWith(linkPath, "/run/") ? "enabled-runtime" : "static";
}

std::string SystemdUnitsProvider::unitObjectPath(const std::string& unitName)
{
    static constexpr char HEX[] {"0123456789abcdef"};
    std::string path {"/org/freedesktop/systemd1/unit/"};

    if (unitName.empty())
    {
        return path + "_";
    }

    for (size_t i = 0; i < unitName.size(); ++i)
    {
        const auto c = static_cast<unsigned char>(unitName[i]);
        const bool isAlpha = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
        const bool isDigit = c >= '0' && c <= '9';

        // Same as systemd's bus_label_escape(): a leading digit is escaped too.
        if (isAlpha || (isDigit && i > 0))
        {
            path += static_cast<char>(c);
        }
        else
        {
            path += '_';
            path += HEX[c >> 4];
            path += HEX[c & 0xF];
        }
    }

    return path;
}

SystemdUnitsProvider::SystemdUnitsProvider(std::shared_ptr<IDBusWrapper> dbusWrapper)
    : SystemdUnitsProvider(std::move(dbusWrapper), defaultSettings())
{
}

SystemdUnitsProvider::SystemdUnitsProvider(std::shared_ptr<IDBusWrapper> dbusWrapper, SystemdUnitsSettings settings)
    : m_dbusWrapper(std::move(dbusWrapper))
    , m_settings(std::move(settings))
{
}

SystemdUnitsProvider::SystemdUnitsProvider()
    : SystemdUnitsProvider(std::make_shared<DBusWrapper>())
{
}

nlohmann::json SystemdUnitsProvider::collect()
{
    nlohmann::json result = nlohmann::json::array();
    std::vector<SystemdUnit> units;
    const auto status = getSystemdUnits(units);
    std::error_code ec;

    if (status == CollectionStatus::Complete)
    {
        m_settings.consecutiveFailures->store(0);
    }
    else if (std::filesystem::is_directory(m_settings.runtimeDirectory, ec))
    {
        // Reporting only what was listed would report the missing units as deleted, so the scan
        // is skipped and the previous inventory kept. A failure that persists must not freeze
        // the inventory, so after MAX_CONSECUTIVE_FAILURES skipped scans what systemd lists is
        // reported; the last skipped scan says so, and later ones log nothing.
        const auto failures = std::min(m_settings.consecutiveFailures->load() + 1, MAX_CONSECUTIVE_FAILURES + 1);
        m_settings.consecutiveFailures->store(failures);

        if (failures <= MAX_CONSECUTIVE_FAILURES)
        {
            const bool unitsFailed = status == CollectionStatus::Failed;
            std::string message {unitsFailed ? "Unable to list the systemd units" : "Unable to list the systemd unit files"};
            message += ", services scan skipped (" + std::to_string(failures) + " of " +
                       std::to_string(MAX_CONSECUTIVE_FAILURES) + ")";

            if (failures == MAX_CONSECUTIVE_FAILURES)
            {
                message += unitsFailed ? "; until systemd answers, the next scans report no services"
                           : "; until systemd answers, the next scans report only the loaded services";
            }

            throw std::runtime_error {message};
        }
    }

    for (const auto& unit : units)
    {
        nlohmann::json row;
        row["id"] = unit.id;
        row["description"] = unit.description;
        row["load_state"] = unit.loadState;
        row["active_state"] = unit.activeState;
        row["sub_state"] = unit.subState;
        row["following"] = unit.following;
        row["object_path"] = unit.objectPath;
        row["job_id"] = unit.jobId;
        row["job_type"] = unit.jobType;
        row["job_path"] = unit.jobPath;
        row["fragment_path"] = unit.fragmentPath;
        row["source_path"] = unit.sourcePath;
        row["user"] = unit.user;
        row["unit_file_state"] = unit.unitFileState;

        result.push_back(std::move(row));
    }

    return result;
}

SystemdUnitsProvider::CollectionStatus SystemdUnitsProvider::getSystemdUnits(std::vector<SystemdUnit>& output)
{
    DBusError err;
    m_dbusWrapper->error_init(&err);

    // Owned for the rest of this scope, and released on every return path below.
    ScopedDBusConnection scopedConnection {m_dbusWrapper, m_dbusWrapper->bus_get_private(DBUS_BUS_SYSTEM, &err)};
    DBusConnection* conn = scopedConnection.get();

    if (!conn || m_dbusWrapper->error_is_set(&err))
    {
        // std::cerr << "Failed to connect to system bus: " << err.message << std::endl;
        m_dbusWrapper->error_free(&err);
        return CollectionStatus::Failed;
    }

    DBusMessage* msg = m_dbusWrapper->message_new_method_call(
                           "org.freedesktop.systemd1", "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", "ListUnits");

    if (!msg)
    {
        // std::cerr << "Failed to create message" << std::endl;
        m_dbusWrapper->error_free(&err);
        return CollectionStatus::Failed;
    }

    DBusMessage* reply = m_dbusWrapper->connection_send_with_reply_and_block(conn, msg, -1, &err);
    m_dbusWrapper->message_unref(msg);

    if (!reply || m_dbusWrapper->error_is_set(&err))
    {
        // std::cerr << "Failed to send message: " << err.message << std::endl;
        m_dbusWrapper->error_free(&err);
        return CollectionStatus::Failed;
    }

    DBusMessageIter iter;

    if (!m_dbusWrapper->message_iter_init(reply, &iter))
    {
        // std::cerr << "Reply has no arguments." << std::endl;
        m_dbusWrapper->message_unref(reply);
        m_dbusWrapper->error_free(&err);
        return CollectionStatus::Failed;
    }

    if (DBUS_TYPE_ARRAY != m_dbusWrapper->message_iter_get_arg_type(&iter))
    {
        // std::cerr << "Expected an array." << std::endl;
        m_dbusWrapper->message_unref(reply);
        m_dbusWrapper->error_free(&err);
        return CollectionStatus::Failed;
    }

    DBusMessageIter arrayIter;
    m_dbusWrapper->message_iter_recurse(&iter, &arrayIter);

    std::unordered_set<std::string> loadedIds;

    while (m_dbusWrapper->message_iter_get_arg_type(&arrayIter) == DBUS_TYPE_STRUCT)
    {
        DBusMessageIter structIter;
        m_dbusWrapper->message_iter_recurse(&arrayIter, &structIter);

        SystemdUnit unit;
        const char* str = nullptr;
        uint32_t jobId;

        // (ssssssouso) → 10 elements
        m_dbusWrapper->message_iter_get_basic(&structIter, &str);
        unit.id = str;
        m_dbusWrapper->message_iter_next(&structIter);
        m_dbusWrapper->message_iter_get_basic(&structIter, &str);
        unit.description = str;
        m_dbusWrapper->message_iter_next(&structIter);
        m_dbusWrapper->message_iter_get_basic(&structIter, &str);
        unit.loadState = str;
        m_dbusWrapper->message_iter_next(&structIter);
        m_dbusWrapper->message_iter_get_basic(&structIter, &str);
        unit.activeState = str;
        m_dbusWrapper->message_iter_next(&structIter);
        m_dbusWrapper->message_iter_get_basic(&structIter, &str);
        unit.subState = str;
        m_dbusWrapper->message_iter_next(&structIter);
        m_dbusWrapper->message_iter_get_basic(&structIter, &str);
        unit.following = str;
        m_dbusWrapper->message_iter_next(&structIter);
        m_dbusWrapper->message_iter_get_basic(&structIter, &str);
        unit.objectPath = str;
        m_dbusWrapper->message_iter_next(&structIter);
        m_dbusWrapper->message_iter_get_basic(&structIter, &jobId);
        unit.jobId = jobId;
        m_dbusWrapper->message_iter_next(&structIter);
        m_dbusWrapper->message_iter_get_basic(&structIter, &str);
        unit.jobType = str;
        m_dbusWrapper->message_iter_next(&structIter);
        m_dbusWrapper->message_iter_get_basic(&structIter, &str);
        unit.jobPath = str;

        // Filter before the per-unit property queries, which cost one D-Bus round trip each.
        // Inactive not-found units are placeholders only referenced by other units' dependencies.
        const bool isPlaceholder = unit.loadState == "not-found" && unit.activeState == "inactive";

        if (isPlaceholder || !Utils::endsWith(unit.id, SERVICE_SUFFIX))
        {
            m_dbusWrapper->message_iter_next(&arrayIter);
            continue;
        }

        Utils::replaceLast(unit.id, SERVICE_SUFFIX, "");
        loadedIds.insert(unit.id);

        // Extra properties
        for (const auto& query : m_propertyQueryList)
        {
            std::string value;

            if (m_dbusWrapper->getProperty(
                        conn, "org.freedesktop.systemd1", unit.objectPath, query.interface, query.propertyName, value))
            {
                if (query.columnName == "fragment_path")
                {
                    unit.fragmentPath = std::move(value);
                }
                else if (query.columnName == "source_path")
                {
                    unit.sourcePath = std::move(value);
                }
                else if (query.columnName == "user")
                {
                    unit.user = std::move(value);
                }
                else if (query.columnName == "unit_file_state")
                {
                    unit.unitFileState = std::move(value);
                }
            }
        }

        output.emplace_back(std::move(unit));

        m_dbusWrapper->message_iter_next(&arrayIter);
    }

    m_dbusWrapper->message_unref(reply);
    m_dbusWrapper->error_free(&err);

    return appendUnloadedUnitFiles(conn, loadedIds, output) ? CollectionStatus::Complete : CollectionStatus::LoadedOnly;
}

unsigned int SystemdUnitsProvider::readSystemdVersion(DBusConnection* conn)
{
    std::string version;

    if (!m_dbusWrapper->getProperty(conn, "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
                                    "org.freedesktop.systemd1.Manager", "Version", version))
    {
        return 0;
    }

    unsigned int major {0};

    for (const auto c : version)
    {
        if (c < '0' || c > '9' || major > 100000)
        {
            break;
        }

        major = major * 10 + static_cast<unsigned int>(c - '0');
    }

    return major;
}


bool SystemdUnitsProvider::appendUnloadedUnitFiles(DBusConnection* conn,
                                                   const std::unordered_set<std::string>& loadedIds,
                                                   std::vector<SystemdUnit>& output)
{
    DBusError err;
    m_dbusWrapper->error_init(&err);

    DBusMessage* msg = m_dbusWrapper->message_new_method_call(
                           "org.freedesktop.systemd1", "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", "ListUnitFiles");

    if (!msg)
    {
        m_dbusWrapper->error_free(&err);
        return false;
    }

    DBusMessage* reply = m_dbusWrapper->connection_send_with_reply_and_block(conn, msg, -1, &err);
    m_dbusWrapper->message_unref(msg);

    if (!reply || m_dbusWrapper->error_is_set(&err))
    {
        m_dbusWrapper->message_unref(reply);
        m_dbusWrapper->error_free(&err);
        return false;
    }

    DBusMessageIter iter;

    if (!m_dbusWrapper->message_iter_init(reply, &iter) || DBUS_TYPE_ARRAY != m_dbusWrapper->message_iter_get_arg_type(&iter))
    {
        m_dbusWrapper->message_unref(reply);
        m_dbusWrapper->error_free(&err);
        return false;
    }

    DBusMessageIter arrayIter;
    m_dbusWrapper->message_iter_recurse(&iter, &arrayIter);

    std::vector<std::pair<std::string, std::string>> entries;

    while (m_dbusWrapper->message_iter_get_arg_type(&arrayIter) == DBUS_TYPE_STRUCT)
    {
        DBusMessageIter structIter;
        m_dbusWrapper->message_iter_recurse(&arrayIter, &structIter);

        // (ss) → path, state
        const char* str = nullptr;
        m_dbusWrapper->message_iter_get_basic(&structIter, &str);
        std::string path {str ? str : ""};
        m_dbusWrapper->message_iter_next(&structIter);
        str = nullptr;
        m_dbusWrapper->message_iter_get_basic(&structIter, &str);
        entries.emplace_back(std::move(path), str ? str : "");

        m_dbusWrapper->message_iter_next(&arrayIter);
    }

    m_dbusWrapper->message_unref(reply);
    m_dbusWrapper->error_free(&err);

    // Aliases by the unit they point to; systemd also reads drop-ins under an alias's name.
    std::map<std::string, std::vector<std::string>> aliasesByTarget;
    std::unordered_set<std::string> aliasPaths;

    for (const auto& [path, state] : entries)
    {
        // A masked unit is a link to /dev/null, whatever form the link takes.
        const auto target = Utils::startsWith(state, "masked") ? std::string {} :
                            aliasTarget(path);

        if (!target.empty())
        {
            aliasesByTarget[target].push_back(std::filesystem::path(path).filename().string());
            aliasPaths.insert(path);
        }
        else if (state == "alias")
        {
            aliasPaths.insert(path);
        }
    }

    std::unordered_set<std::string> addedIds;
    std::optional<unsigned int> systemdVersion;
    std::optional<HostFacts> facts;

    for (const auto& [path, state] : entries)
    {
        const auto name = std::filesystem::path(path).filename().string();

        // Templates ("foo@.service") are not units; their instances come from ListUnits.
        if (!Utils::endsWith(name, SERVICE_SUFFIX) || Utils::endsWith(name, std::string("@") + SERVICE_SUFFIX) ||
                aliasPaths.count(path))
        {
            continue;
        }

        auto id = name;
        Utils::replaceLast(id, SERVICE_SUFFIX, "");

        if (loadedIds.count(id) || addedIds.count(id))
        {
            continue;
        }

        // Same values systemd reports for a loaded unit that is stopped, so loading or
        // unloading the unit does not change its inventory row. A masked unit has none.
        UnitFileValues fileValues;

        if (!Utils::startsWith(state, "masked"))
        {
            if (!systemdVersion)
            {
                systemdVersion = readSystemdVersion(conn);
                facts = readHostFacts();
            }

            auto aliases = aliasesByTarget[name];
            std::sort(aliases.begin(), aliases.end());

            // A file removed since it was listed is no longer installed.
            if (readUnitFileValues(path, name, dropInDirs(name, aliases, m_settings.unitSearchPaths, *systemdVersion),
                                   *systemdVersion, *facts, fileValues) == ReadResult::Missing)
            {
                continue;
            }
        }

        addedIds.insert(id);

        SystemdUnit unit;
        unit.id = std::move(id);
        unit.description = fileValues.description.empty() ? name : fileValues.description;
        // Not loaded, so systemd has no load state for it; load_state is not part of the inventory.
        unit.loadState = "";
        unit.activeState = "inactive";
        unit.subState = "dead";
        unit.objectPath = unitObjectPath(name);
        unit.jobId = 0;
        unit.jobPath = "/";
        unit.fragmentPath = path;
        unit.sourcePath = fileValues.sourcePath;
        unit.user = fileValues.user;
        unit.unitFileState = state;

        output.emplace_back(std::move(unit));
    }

    // Enabled instances of an installed template are installed too, loaded or not.
    std::map<std::string, std::pair<std::string, std::string>> templates;

    for (const auto& [path, state] : entries)
    {
        const auto name = std::filesystem::path(path).filename().string();

        if (Utils::endsWith(name, std::string("@") + SERVICE_SUFFIX) && !aliasPaths.count(path))
        {
            templates.emplace(name, std::make_pair(path, state));
        }
    }

    for (const auto& [name, linkPath] : enabledInstances(m_settings.unitSearchPaths))
    {
        auto id = name;
        Utils::replaceLast(id, SERVICE_SUFFIX, "");
        const auto templateIt = templates.find(unitPrefix(name) + "@" + SERVICE_SUFFIX);

        if (loadedIds.count(id) || addedIds.count(id) || templateIt == templates.end() ||
                Utils::startsWith(templateIt->second.second, "masked"))
        {
            continue;
        }

        if (!systemdVersion)
        {
            systemdVersion = readSystemdVersion(conn);
            facts = readHostFacts();
        }

        UnitFileValues fileValues;
        const auto& templatePath = templateIt->second.first;

        if (readUnitFileValues(templatePath, name, dropInDirs(name, {}, m_settings.unitSearchPaths, *systemdVersion),
                               *systemdVersion, *facts, fileValues) == ReadResult::Missing)
        {
            continue;
        }

        addedIds.insert(id);

        SystemdUnit unit;
        unit.id = std::move(id);
        unit.description = fileValues.description.empty() ? name : fileValues.description;
        unit.loadState = "";
        unit.activeState = "inactive";
        unit.subState = "dead";
        unit.objectPath = unitObjectPath(name);
        unit.jobId = 0;
        unit.jobPath = "/";
        unit.fragmentPath = templatePath;
        unit.sourcePath = fileValues.sourcePath;
        unit.user = fileValues.user;
        unit.unitFileState = instanceLinkState(linkPath);

        output.emplace_back(std::move(unit));
    }

    return true;
}
