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
#include <unistd.h>
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <filesystem>
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

    void parseUnitLine(const std::string& line, std::string& section, UnitFileValues& values)
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

    // Drop-in directory names of one unit name: "a-b.service.d", then its prefixes
    // "a-.service.d" (hierarchical drop-ins), most specific first.
    std::vector<std::string> nameDropInDirs(const std::string& unitName, bool withPrefixes)
    {
        std::vector<std::string> names {unitName + ".d"};

        if (withPrefixes && Utils::endsWith(unitName, SERVICE_SUFFIX))
        {
            const auto prefix = unitName.substr(0, unitName.size() - std::strlen(SERVICE_SUFFIX));

            for (auto pos = prefix.rfind('-'); pos != std::string::npos && pos > 0; pos = prefix.rfind('-', pos - 1))
            {
                names.push_back(prefix.substr(0, pos + 1) + SERVICE_SUFFIX + ".d");
            }
        }

        return names;
    }

    // Drop-in directories in systemd's order (unit_file_find_dropin_paths()): the unit's own
    // and prefix directories in every search path, then the same for each alias, then
    // "service.d" in every search path.
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
            const auto dirNames = nameDropInDirs(name, withPrefixes);

            for (const auto& searchPath : searchPaths)
            {
                for (const auto& dirName : dirNames)
                {
                    dirs.push_back(std::filesystem::path(searchPath) / dirName);
                }
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

    // Values of an unloaded unit: its fragment, then its drop-ins. Specifiers (%H, %n...) are
    // kept literal; systemd expands them only when it loads the unit.
    ReadResult readUnitFileValues(const std::string& fragmentPath,
                                  const std::vector<std::filesystem::path>& dropInDirectories,
                                  UnitFileValues& values)
    {
        std::string content;
        const auto result = readRegularFile(fragmentPath, content);

        if (result != ReadResult::Read)
        {
            return result;
        }

        std::istringstream fragment {content};
        values = SystemdUnitsProvider::parseUnitFile(fragment, std::move(values));

        for (const auto& dropInPath : dropInFiles(dropInDirectories))
        {
            if (readRegularFile(dropInPath, content) == ReadResult::Read)
            {
                std::istringstream dropIn {content};
                values = SystemdUnitsProvider::parseUnitFile(dropIn, std::move(values));
            }
        }

        return result;
    }
}

UnitFileValues SystemdUnitsProvider::parseUnitFile(std::istream& input, UnitFileValues values)
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

        parseUnitLine(continued ? pending + part : part, section, values);
        pending.clear();
        continued = false;
    }

    if (continued)
    {
        parseUnitLine(pending, section, values);
    }

    return values;
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
        // Nothing was listed, so there is nothing to report: the scan is skipped and the previous
        // inventory kept, however long the failure lasts.
        if (status == CollectionStatus::Failed)
        {
            throw std::runtime_error {"Unable to list the systemd units, services scan skipped"};
        }

        // Reporting only the loaded units would report the unloaded ones as deleted, so the scan
        // is skipped, unless the failure persists and the loaded units would stop being updated.
        const auto failures = std::min(m_settings.consecutiveFailures->load() + 1, MAX_CONSECUTIVE_FAILURES);
        m_settings.consecutiveFailures->store(failures);

        if (failures < MAX_CONSECUTIVE_FAILURES)
        {
            throw std::runtime_error
            {
                "Unable to list the systemd unit files, services scan skipped (" + std::to_string(failures) + " of " +
                std::to_string(MAX_CONSECUTIVE_FAILURES - 1) + " before reporting only the loaded units)"
            };
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
            }

            auto aliases = aliasesByTarget[name];
            std::sort(aliases.begin(), aliases.end());

            // A file removed since it was listed is no longer installed.
            if (readUnitFileValues(path, dropInDirs(name, aliases, m_settings.unitSearchPaths, *systemdVersion),
                                   fileValues) == ReadResult::Missing)
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

    return true;
}
