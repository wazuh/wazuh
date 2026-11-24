/*
 * Wazuh SYSINFO
 * Copyright (C) Wazuh Inc.
 * November 19, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PACKAGE_DB_PARSER_HPP
#define _PACKAGE_DB_PARSER_HPP

#include "rpmDbNdbReader.hpp"
#include "rpmDbSqliteReader.hpp"
#include "rpmHeaderBlobParser.hpp"

#if defined(__linux__)
#include "berkeleyDbWrapper.h"

#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <pwd.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <csignal>
#include <cstring>

// The package builders compile against system headers older than Linux 3.5, which do not name it.
#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif
#endif

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <optional>
#include <random>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

/// @brief Reading of the package databases of a filesystem that is not the running host.
///
/// Container image scanning and container runtime security both need the packages a
/// container filesystem holds, and must report the same ones for the same files. This is
/// the one place that knows how to read them. It works on bytes and in-image paths, never
/// on the host filesystem, so a caller decides how the files are obtained (a composed image
/// layer, `/proc/<pid>/root`) and hands them over as a map from path to content.
///
/// Formats: dpkg (`status`, and the `status.d` directory distroless images use), apk (both
/// database locations), rpm in sqlite, ndb and Berkeley DB. Berkeley DB needs libdb and is
/// read on Linux only.
///
/// Nothing here throws for malformed content: an unreadable database costs its own packages
/// and is reported, and the other databases are still read. The host package inventory does
/// not use this code.
namespace PackageDb
{
    /// @brief One installed package. A value the database does not carry is empty.
    struct Package
    {
        std::string name;
        std::string version;       ///< dpkg: as written. apk: as written. rpm: `[epoch:]version[-release]`.
        std::string architecture;
        std::string type;          ///< Package format: deb, apk or rpm.
        std::string vendor;
        std::string installed;     ///< ISO 8601 install date, when the database records one.
        std::string category;
        std::string description;
        std::string priority;
        std::string multiarch;
        std::string source;        ///< dpkg: Source. apk: origin. rpm: source package file name.
        std::string packageDbPath; ///< Path of the database the package was read from.
        long long size {0};        ///< Installed size in bytes.
    };

    /// @brief Files of a filesystem that may hold a package database.
    ///
    /// Keyed by the path inside the filesystem, relative and normalized: `var/lib/dpkg/status`,
    /// no leading slash, no `./`. The value is the whole content of the file.
    using Files = std::map<std::string, std::string>;

    /// @brief What happened to one package database.
    struct DatabaseReport
    {
        std::string path;        ///< Database path, or the directory for `status.d`.
        std::size_t packages {0}; ///< Packages read from it.
        bool skipped {false};    ///< Present, but another location of the same database was read instead.
        std::string error;       ///< Empty when the database was read. Otherwise why it was not.
        /// The failure says nothing about the database: it was a cancel, a timeout, or the lack of a process, a
        /// file or an account, so reading again can succeed. A database that is damaged is not transient.
        bool transient {false};
        std::string warning;     ///< Something worth a log line that did not stop the read.
    };

    /// @brief Packages read from the files, and what was done with each database found.
    struct Result
    {
        std::vector<Package> packages;
        std::vector<DatabaseReport> databases;
    };

    constexpr auto FORMAT_DPKG { "deb" };
    constexpr auto FORMAT_APK { "apk" };
    constexpr auto FORMAT_RPM { "rpm" };

    constexpr auto DPKG_STATUS_PATH { "var/lib/dpkg/status" };
    /// Read only when `status` is absent: a distroless image has no `status`, and a
    /// Debian one that has both is described by `status`.
    constexpr auto DPKG_STATUS_D_DIRECTORY { "var/lib/dpkg/status.d" };
    constexpr auto DPKG_CHECKSUM_SUFFIX { ".md5sums" };

    /// @brief Whether Berkeley DB rpm databases can be read on this platform.
    constexpr bool BERKELEY_DB_SUPPORTED
    {
#if defined(__linux__)
        true
#else
        false
#endif
    };

    constexpr auto BERKELEY_DB_UNSUPPORTED_ERROR { "rpm Berkeley DB not supported on this platform" };

    /// The account the read of a Berkeley DB file runs as when the process is root. Not the agent's own
    /// account: that one can read the agent's keys, and what runs here parses bytes from an image. `nobody`
    /// exists on every system this runs on and owns nothing.
    constexpr auto BERKELEY_DB_ACCOUNT { "nobody" };

    /// How long one Berkeley DB file may take to read. libdb is given the bytes of a file an image
    /// carries, and a damaged one can send it into an endless loop. Reading a real database of a few
    /// hundred packages takes milliseconds, so the limit only ever applies to a file that is not one.
    constexpr std::chrono::milliseconds BERKELEY_DB_READ_DEADLINE { std::chrono::seconds { 30 } };

    /// @brief Run the Berkeley DB read differently, which is how the tests make it fast or fail.
    struct BerkeleyDbOptions
    {
        std::chrono::milliseconds deadline { BERKELEY_DB_READ_DEADLINE };

        /// The account the child drops to when the process is root. Looked up before the fork. When it does
        /// not exist the read does not start, since libdb must not run with root privileges.
        std::string account { BERKELEY_DB_ACCOUNT };

        /// Runs in the child process, given the path of the private copy and the database path.
        /// Returns the reply the child sends back. Empty means the real read.
        std::function<std::string(const std::string&, const std::string&)> child;

        /// Polled while the child runs. When it returns true the child is killed and reaped at once, so
        /// a shutdown does not wait for a read. Empty means never.
        std::function<bool()> stop;
    };

    /// @brief The database files, in the order they are preferred.
    ///
    /// Locations of one format hold the same conceptual database, so only the first one
    /// present is read: an image that carries a file at both reports its packages once.
    /// rpm keeps its database under `var` on the Red Hat family and under `usr` on Fedora
    /// and the SUSE family. A Berkeley DB `Packages` file is the last choice because rpm
    /// 4.16 and later can leave a stale one next to the database that replaced it.
    struct Location
    {
        const char* path;
        const char* format;
        bool berkeleyDb {false}; ///< An rpm Berkeley DB file, which is read through libdb.
    };

    static inline const std::vector<Location>& databaseLocations()
    {
        static const std::vector<Location> LOCATIONS
        {
            {DPKG_STATUS_PATH, FORMAT_DPKG},
            {"lib/apk/db/installed", FORMAT_APK},
            {"usr/lib/apk/db/installed", FORMAT_APK},
            {"var/lib/rpm/rpmdb.sqlite", FORMAT_RPM},
            {"usr/lib/sysimage/rpm/rpmdb.sqlite", FORMAT_RPM},
            {"var/lib/rpm/Packages.db", FORMAT_RPM},
            {"usr/lib/sysimage/rpm/Packages.db", FORMAT_RPM},
#if defined(__linux__)
            {"var/lib/rpm/Packages", FORMAT_RPM, true},
            {"usr/lib/sysimage/rpm/Packages", FORMAT_RPM, true},
#endif
        };

        return LOCATIONS;
    }

    /// @brief True for a file directly under `status.d` that holds one package.
    static inline bool isStatusDEntry(const std::string& path)
    {
        const std::string directory { std::string { DPKG_STATUS_D_DIRECTORY } + "/" };
        const std::string suffix { DPKG_CHECKSUM_SUFFIX };

        if (path.size() <= directory.size() || path.compare(0, directory.size(), directory) != 0)
        {
            return false;
        }

        const auto name { path.substr(directory.size()) };

        return name.find('/') == std::string::npos &&
               !(name.size() >= suffix.size() && name.compare(name.size() - suffix.size(), suffix.size(), suffix) == 0);
    }

    /// @brief True when @p path is a file this parser reads, so a caller keeps its content.
    static inline bool isDatabasePath(const std::string& path)
    {
        const auto& locations { databaseLocations() };

        return std::any_of(locations.begin(), locations.end(), [&path](const Location & location)
        {
            return path == location.path;
        }) || isStatusDEntry(path);
    }

    namespace detail
    {
        /// dpkg reports the installed size in kibibytes, the tables store bytes.
        constexpr long long DPKG_SIZE_UNIT { 1024 };

        /// The largest `long long`, without pulling a header in for it.
        constexpr long long LARGEST_SIZE { static_cast<long long>(~0ULL >> 1) };

        static inline std::string trim(const std::string& value)
        {
            const auto begin { value.find_first_not_of(" \t\r\n") };

            if (begin == std::string::npos)
            {
                return {};
            }

            const auto end { value.find_last_not_of(" \t\r\n") };
            return value.substr(begin, end - begin + 1);
        }

        /// @brief Parse the leading integer of a field, without throwing.
        ///
        /// This runs in the child process that reads a Berkeley DB file, where an exception would walk the
        /// unwinder and take a lock of the dynamic loader that another thread of the parent may hold.
        /// @return False for anything that is not a number, and for a value out of range.
        static inline bool parseInteger(const std::string& value, long long& number)
        {
            const auto* begin { value.c_str() };
            char* end { nullptr };

            errno = 0;
            number = std::strtoll(begin, &end, 10);

            return end != begin && errno != ERANGE;
        }

        /// @brief Parse a size field and scale it by @p unit.
        /// @return 0 for anything that is not a number, and for a value that overflows once scaled.
        static inline long long parseSize(const std::string& value, long long unit)
        {
            long long number { 0 };

            if (!parseInteger(value, number) || number > LARGEST_SIZE / unit || number < (-LARGEST_SIZE - 1) / unit)
            {
                return 0;
            }

            return number * unit;
        }

        /// @brief Split a database into stanzas, which are separated by a blank line.
        ///
        /// Lines are handed on with their leading whitespace intact, because dpkg marks the
        /// continuation of a field with it.
        static inline std::vector<std::string> splitStanzas(const std::string& content)
        {
            std::vector<std::string> stanzas;
            std::string current;
            std::istringstream stream { content };
            std::string line;

            while (std::getline(stream, line))
            {
                if (!line.empty() && line.back() == '\r')
                {
                    line.pop_back();
                }

                if (line.empty())
                {
                    if (!current.empty())
                    {
                        stanzas.push_back(std::move(current));
                        current.clear();
                    }

                    continue;
                }

                current += line;
                current += '\n';
            }

            if (!current.empty())
            {
                stanzas.push_back(std::move(current));
            }

            return stanzas;
        }

        /// @brief Read one dpkg stanza into its fields.
        ///
        /// A field continues on the following lines when they start with whitespace, which is
        /// how a multi-line Description is written.
        static inline std::map<std::string, std::string> dpkgFields(const std::string& stanza)
        {
            std::map<std::string, std::string> fields;
            std::istringstream stream { stanza };
            std::string line;
            std::string currentKey;

            while (std::getline(stream, line))
            {
                if (line.empty())
                {
                    continue;
                }

                if (line.front() == ' ' || line.front() == '\t')
                {
                    if (!currentKey.empty())
                    {
                        fields[currentKey] += "\n" + trim(line);
                    }

                    continue;
                }

                const auto colon { line.find(':') };

                if (colon == std::string::npos)
                {
                    continue;
                }

                currentKey = trim(line.substr(0, colon));
                fields[currentKey] = trim(line.substr(colon + 1));
            }

            return fields;
        }

        static inline std::string field(const std::map<std::string, std::string>& fields, const std::string& key)
        {
            const auto entry { fields.find(key) };

            if (entry == fields.end())
            {
                return {};
            }

            return entry->second;
        }

        /// @brief First line of a value, which is the short form of a dpkg description.
        static inline std::string firstLine(const std::string& value)
        {
            const auto newline { value.find('\n') };
            return newline == std::string::npos ? value : value.substr(0, newline);
        }

        /// @brief Build the package a dpkg stanza describes.
        /// @return False when the stanza is not an installed package.
        static inline bool dpkgPackage(const std::map<std::string, std::string>& fields,
                                       const std::string& dbPath,
                                       Package& package)
        {
            const auto name { field(fields, "Package") };

            // The dpkg status is "SELECTION_STATE FLAG PACKAGE_STATE". Only "ok installed"
            // means the package is really there: a removed package keeps its stanza with a
            // different state.
            if (name.empty() || field(fields, "Status").find("ok installed") == std::string::npos)
            {
                return false;
            }

            package = {};
            package.name = name;
            package.version = field(fields, "Version");
            package.architecture = field(fields, "Architecture");
            package.type = FORMAT_DPKG;
            package.vendor = field(fields, "Maintainer");
            package.category = field(fields, "Section");
            package.description = firstLine(field(fields, "Description"));
            package.priority = field(fields, "Priority");
            package.multiarch = field(fields, "Multi-Arch");
            package.source = field(fields, "Source");
            package.size = parseSize(field(fields, "Installed-Size"), DPKG_SIZE_UNIT);
            package.packageDbPath = dbPath;

            return true;
        }

        /// @brief The version as the distribution expresses it: `[epoch:]version-release`.
        ///
        /// The epoch is part of how rpm orders versions, so it is kept whenever the package
        /// carries one, including an explicit zero. A package with no epoch tag at all is
        /// reported without the prefix, which is how the package manager prints it.
        static inline std::string rpmVersion(const RpmHeaderBlob::Package& header)
        {
            std::string version;

            if (!header.epoch.empty())
            {
                version = header.epoch + ":";
            }

            version += header.version;

            if (!header.release.empty())
            {
                version += "-" + header.release;
            }

            return version;
        }

        /// @brief Seconds since the epoch as `YYYY-MM-DDTHH:MM:SS.000Z`, by arithmetic alone.
        ///
        /// This runs in the child process that reads a Berkeley DB file. The libc time functions take a
        /// lock of their own (the time zone one), which fork does not reset and which the threads of the
        /// parent take all the time to log, so the child could wait for it until its deadline.
        static inline std::string isoTimestamp(uint32_t seconds)
        {
            // Days since 1970-01-01 to a civil date, from Howard Hinnant's days_from_civil inverse.
            const auto days { static_cast<int64_t>(seconds / 86400U) + 719468 };
            const auto era { days / 146097 };
            const auto dayOfEra { days - era * 146097 };
            const auto yearOfEra { (dayOfEra - dayOfEra / 1460 + dayOfEra / 36524 - dayOfEra / 146096) / 365 };
            const auto dayOfYear { dayOfEra - (365 * yearOfEra + yearOfEra / 4 - yearOfEra / 100) };
            const auto monthIndex { (5 * dayOfYear + 2) / 153 };
            const auto day { dayOfYear - (153 * monthIndex + 2) / 5 + 1 };
            const auto month { monthIndex < 10 ? monthIndex + 3 : monthIndex - 9 };
            const auto year { yearOfEra + era * 400 + (month <= 2 ? 1 : 0) };
            const auto secondOfDay { seconds % 86400U };

            const auto digits = [](int64_t value, int width)
            {
                std::string text(static_cast<std::size_t>(width), '0');

                for (int position = width - 1; position >= 0; --position)
                {
                    text[static_cast<std::size_t>(position)] = static_cast<char>('0' + value % 10);
                    value /= 10;
                }

                return text;
            };

            return digits(year, 4) + "-" + digits(month, 2) + "-" + digits(day, 2) + "T" +
                   digits(secondOfDay / 3600, 2) + ":" + digits(secondOfDay % 3600 / 60, 2) + ":" +
                   digits(secondOfDay % 60, 2) + ".000Z";
        }

        /// @brief The install date as ISO 8601, empty when the database records none.
        static inline std::string rpmInstallDate(const std::string& timestamp)
        {
            long long seconds { 0 };

            if (!parseInteger(timestamp, seconds))
            {
                return {};
            }

            return isoTimestamp(static_cast<uint32_t>(seconds));
        }

        /// @brief Turn one rpm header blob into a package, appended to @p packages when valid.
        static inline void collectRpmBlob(const uint8_t* blob,
                                          std::size_t size,
                                          const std::string& dbPath,
                                          std::vector<Package>& packages)
        {
            const auto header { RpmHeaderBlob::parse(blob, size) };

            // The signing keys rpm keeps in the database are not installed software.
            if (!header.valid || header.name.empty() || header.name == "gpg-pubkey")
            {
                return;
            }

            Package package;
            package.name = header.name;
            package.version = rpmVersion(header);
            package.architecture = header.architecture;
            package.type = FORMAT_RPM;
            package.vendor = header.vendor;
            package.installed = rpmInstallDate(header.installTime);
            package.category = header.group;
            package.description = header.description;
            package.source = header.source;
            package.size = parseSize(header.size, 1);
            package.packageDbPath = dbPath;

            packages.push_back(std::move(package));
        }

#if defined(__linux__)
        /// @brief Magic number of a Berkeley DB hash database, at byte 12 of its first page.
        constexpr uint32_t BERKELEY_HASH_MAGIC { 0x00061561 };
        constexpr std::size_t BERKELEY_MAGIC_OFFSET { 12 };

        static inline bool isBerkeleyHashDatabase(const std::string& content)
        {
            if (content.size() < BERKELEY_MAGIC_OFFSET + sizeof(uint32_t))
            {
                return false;
            }

            const auto* bytes { reinterpret_cast<const uint8_t*>(content.data()) + BERKELEY_MAGIC_OFFSET };
            const auto bigEndian { RpmHeaderBlob::toUint32BE(bytes) };
            const auto littleEndian { static_cast<uint32_t>(bytes[0]) | (static_cast<uint32_t>(bytes[1]) << 8) |
                                      (static_cast<uint32_t>(bytes[2]) << 16) | (static_cast<uint32_t>(bytes[3]) << 24) };

            return bigEndian == BERKELEY_HASH_MAGIC || littleEndian == BERKELEY_HASH_MAGIC;
        }

        /// @brief A directory only the current user can enter, removed on every path out.
        ///
        /// libdb opens a database by path, so the bytes have to be on disk for it. They are
        /// written into a directory that is created private, with an unpredictable name, and
        /// that goes away when this object does, whether the read succeeded, failed or threw.
        class PrivateDirectory final
        {
            public:
                PrivateDirectory()
                {
                    std::error_code error;
                    const auto base { std::filesystem::temp_directory_path(error) };

                    if (error)
                    {
                        throw std::runtime_error { "no temporary directory is available" };
                    }

                    std::random_device device;

                    for (int attempt = 0; attempt < 16; ++attempt)
                    {
                        std::ostringstream name;
                        name << "wazuh_package_db_" << std::hex << device() << device();
                        const auto candidate { base / name.str() };

                        // The mode is part of the call that creates the directory, so there
                        // is no moment at which another user could have entered it.
                        if (::mkdir(candidate.c_str(), S_IRWXU) == 0)
                        {
                            m_path = candidate;
                            return;
                        }
                    }

                    throw std::runtime_error { "a private temporary directory could not be created" };
                }

                ~PrivateDirectory()
                {
                    std::error_code error;
                    std::filesystem::remove_all(m_path, error);
                }

                PrivateDirectory(const PrivateDirectory&) = delete;
                PrivateDirectory& operator=(const PrivateDirectory&) = delete;

                const std::filesystem::path& path() const
                {
                    return m_path;
                }

            private:
                std::filesystem::path m_path;
        };

        /// A reply holds the packages of one database, so it is as large as they are. The module has no cap
        /// on the packages of an image, so the limit is the one on the database the packages come from.
        constexpr std::size_t BERKELEY_REPLY_LIMIT { 64 * 1024 * 1024 };

        /// The shortest a serialized package can be: twelve strings with their lengths, and the size.
        constexpr std::size_t BERKELEY_MIN_PACKAGE_REPLY { 12 * sizeof(uint32_t) + sizeof(int64_t) };

        /// The child ends itself this long after the deadline if nothing else ended it.
        constexpr unsigned int CHILD_GRACE_SECONDS { 2 };

        /// Exit statuses of a child that could not start its read. Any other non-zero one is the read's own.
        constexpr int CHILD_EXIT_EXCEPTION { 2 };
        constexpr int CHILD_EXIT_REPLY { 3 };
        constexpr int CHILD_EXIT_ORPHANED { 4 };
        constexpr int CHILD_EXIT_PRIVILEGES { 70 };
        constexpr int CHILD_EXIT_UNREADABLE { 71 };

        /// How much more address space than the parent had at the fork the child may use. The limit is
        /// relative because the parent's own size is not a constant: a modulesd with many modules loaded
        /// is far larger than a test binary, and a sanitizer build reserves terabytes. The child starts as
        /// a copy of the parent, so what counts is what it adds, and reading a database of 64 MiB at most
        /// needs a fraction of this.
        constexpr std::size_t CHILD_MEMORY_HEADROOM { 768UL * 1024 * 1024 };

        /// How often a running child is checked against the stop request, in milliseconds.
        constexpr int STOP_CHECK_INTERVAL { 50 };

        constexpr char LIMIT_SET { 'N' };
        constexpr char LIMIT_NOT_SET { 'L' };

        constexpr char REPLY_PACKAGES { 'P' };
        constexpr char REPLY_ERROR { 'E' };

        static inline void putUint32(std::string& output, uint32_t value)
        {
            output.append(reinterpret_cast<const char*>(&value), sizeof(value));
        }

        static inline void putString(std::string& output, const std::string& value)
        {
            putUint32(output, static_cast<uint32_t>(value.size()));
            output += value;
        }

        /// @brief The reply of a child that read its database. Same machine, so the host byte order.
        static inline std::string serializePackages(const std::vector<Package>& packages)
        {
            std::string reply { REPLY_PACKAGES };
            putUint32(reply, static_cast<uint32_t>(packages.size()));

            for (const auto& package : packages)
            {
                for (const auto* value :
                        {
                            &package.name, &package.version, &package.architecture, &package.type,
                            &package.vendor, &package.installed, &package.category, &package.description,
                            &package.priority, &package.multiarch, &package.source, &package.packageDbPath
                        })
                {
                    putString(reply, *value);
                }

                const auto size { static_cast<int64_t>(package.size) };
                reply.append(reinterpret_cast<const char*>(&size), sizeof(size));
            }

            return reply;
        }

        /// @brief The reply of a child that could not read its database.
        static inline std::string serializeError(const std::string& message)
        {
            std::string reply { REPLY_ERROR };
            putString(reply, message);
            return reply;
        }

        /// @brief Walks a reply without ever reading past its end.
        class ReplyReader final
        {
            public:
                explicit ReplyReader(const std::string& reply)
                    : m_reply { reply }
                {
                }

                bool uint32(uint32_t& value)
                {
                    return copy(&value, sizeof(value));
                }

                bool int64(int64_t& value)
                {
                    return copy(&value, sizeof(value));
                }

                bool string(std::string& value)
                {
                    uint32_t size { 0 };

                    if (!uint32(size) || size > m_reply.size() - m_position)
                    {
                        return false;
                    }

                    value.assign(m_reply, m_position, size);
                    m_position += size;
                    return true;
                }

                bool byte(char& value)
                {
                    return copy(&value, 1);
                }

                std::size_t remaining() const
                {
                    return m_reply.size() - m_position;
                }

            private:
                bool copy(void* destination, std::size_t size)
                {
                    if (size > m_reply.size() - m_position)
                    {
                        return false;
                    }

                    std::memcpy(destination, m_reply.data() + m_position, size);
                    m_position += size;
                    return true;
                }

                const std::string& m_reply;
                std::size_t m_position { 0 };
        };

        /// @brief Read a reply.
        /// @return False when it is malformed. Otherwise either @p packages or @p error is filled.
        static inline bool parseReply(const std::string& reply, std::vector<Package>& packages, std::string& error)
        {
            ReplyReader reader { reply };
            char kind { 0 };

            if (!reader.byte(kind))
            {
                return false;
            }

            if (kind == REPLY_ERROR)
            {
                return reader.string(error) && reader.remaining() == 0 && !error.empty();
            }

            uint32_t count { 0 };

            if (kind != REPLY_PACKAGES || !reader.uint32(count) || count > reader.remaining() / BERKELEY_MIN_PACKAGE_REPLY)
            {
                return false;
            }

            std::vector<Package> read;
            read.reserve(count);

            for (uint32_t index = 0; index < count; ++index)
            {
                Package package;
                int64_t size { 0 };

                for (auto* value :
                        {
                            &package.name, &package.version, &package.architecture, &package.type,
                            &package.vendor, &package.installed, &package.category, &package.description,
                            &package.priority, &package.multiarch, &package.source, &package.packageDbPath
                        })
                {
                    if (!reader.string(*value))
                    {
                        return false;
                    }
                }

                if (!reader.int64(size))
                {
                    return false;
                }

                package.size = static_cast<long long>(size);
                read.push_back(std::move(package));
            }

            if (reader.remaining() != 0)
            {
                return false;
            }

            packages = std::move(read);
            return true;
        }

        /// @brief The real read of a database, run in the child: every header blob that parses.
        static inline std::string readBerkeleyDbFile(const std::string& file, const std::string& dbPath)
        {
            std::vector<Package> packages;

            try
            {
                BerkeleyDbWrapper database { file };
                DBT key;
                DBT data;

                // The first record of the file is rpm's own bookkeeping, not a header blob.
                // A record that does not parse as a header, that one included, is skipped.
                int32_t status { 0 };

                while ((status = database.getRow(key, data)) == 0)
                {
                    collectRpmBlob(static_cast<const uint8_t*>(data.data), data.size, dbPath, packages);
                }

                // Only the end of the data ends the read. Any other answer is a file damaged after its
                // first records, whose packages so far are a part of the list and not the list.
                if (status != DB_NOTFOUND)
                {
                    return serializeError("the database could not be read to its end (libdb error " + std::to_string(status) + ")");
                }
            }
            catch (const std::exception& exception)
            {
                return serializeError(exception.what());
            }

            return serializePackages(packages);
        }

        /// @brief Close with close_range every descriptor except 0, 1, 2 and @p keep.
        /// @return False when the kernel has no close_range (before 5.9) or refused it.
        static inline bool closeByRange(int keep)
        {
#if defined(SYS_close_range)
            constexpr unsigned int LAST { ~0U };
            const auto first { static_cast<unsigned int>(keep) };
            bool closed { true };

            if (keep > 3)
            {
                closed = syscall(SYS_close_range, 3U, first - 1, 0U) == 0;
            }

            return closed && syscall(SYS_close_range, first + 1, LAST, 0U) == 0;
#else
            static_cast<void>(keep);
            return false;
#endif
        }

        /// @brief Close every open descriptor except 0, 1, 2 and @p keep, found by listing `/proc/self/fd`.
        ///
        /// The directory is read with the system call itself: it allocates nothing and takes no lock, which
        /// matters in a forked child. A pass that closed something is followed by another, since closing
        /// while the directory is read can move the entries.
        /// @return False when the directory cannot be listed.
        static inline bool closeByListing(int keep)
        {
            struct DirectoryEntry
            {
                uint64_t inode;
                int64_t offset;
                unsigned short length;
                unsigned char type;
                char name[1];
            };

            const auto directory { open("/proc/self/fd", O_RDONLY | O_DIRECTORY | O_CLOEXEC) };

            if (directory < 0)
            {
                return false;
            }

            alignas(8) char buffer[4096];
            bool closedAny { true };
            bool listed { true };

            while (closedAny && listed)
            {
                closedAny = false;

                if (lseek(directory, 0, SEEK_SET) < 0)
                {
                    listed = false;
                    break;
                }

                while (true)
                {
                    const auto count { syscall(SYS_getdents64, directory, buffer, sizeof(buffer)) };

                    if (count < 0)
                    {
                        listed = false;
                        break;
                    }

                    if (count == 0)
                    {
                        break;
                    }

                    for (long position = 0; position < count;)
                    {
                        const auto* entry { reinterpret_cast<const DirectoryEntry*>(buffer + position) };
                        position += entry->length;

                        int descriptor { 0 };
                        const char* digit { entry->name };

                        for (; *digit >= '0' && *digit <= '9'; ++digit)
                        {
                            descriptor = descriptor * 10 + (*digit - '0');
                        }

                        // "." and ".." are not numbers, and the directory's own descriptor must outlive the listing.
                        if (digit == entry->name || *digit != '\0' || descriptor <= STDERR_FILENO ||
                                descriptor == keep || descriptor == directory)
                        {
                            continue;
                        }

                        closedAny = close(descriptor) == 0 || closedAny;
                    }
                }
            }

            close(directory);
            return listed;
        }

        /// @brief Close every descriptor from 3 up to the soft limit of the process, except @p keep.
        static inline void closeByLimit(int keep)
        {
            // A limit too large to walk is the largest the kernel allows by default.
            constexpr long WALKABLE { 1L << 20 };
            long limit { sysconf(_SC_OPEN_MAX) };
            rlimit current;

            if (getrlimit(RLIMIT_NOFILE, &current) == 0 && current.rlim_cur != RLIM_INFINITY)
            {
                limit = static_cast<long>(std::min<rlim_t>(current.rlim_cur, static_cast<rlim_t>(WALKABLE)));
            }
            else if (limit <= 0 || limit > WALKABLE)
            {
                limit = WALKABLE;
            }

            for (int descriptor = STDERR_FILENO + 1; descriptor < limit; ++descriptor)
            {
                if (descriptor != keep)
                {
                    close(descriptor);
                }
            }
        }

        /// @brief Close every descriptor the process inherited except 0, 1, 2 and @p keep.
        ///
        /// close_range when the kernel has it. A kernel that does not (RHEL 8 runs 4.18) is served by listing
        /// the open descriptors, and when even that is impossible by closing every number up to the limit.
        static inline void closeInheritedDescriptors(int keep)
        {
            if (!closeByRange(keep) && !closeByListing(keep))
            {
                closeByLimit(keep);
            }
        }

        static inline std::string describeDuration(std::chrono::milliseconds duration)
        {
            return duration.count() % 1000 == 0 ? std::to_string(duration.count() / 1000) + " s"
                   : std::to_string(duration.count()) + " ms";
        }

        /// @brief The size of this process's address space in bytes, 0 when it cannot be read.
        static inline std::size_t processSize()
        {
            std::ifstream statm { "/proc/self/statm" };
            std::size_t pages { 0 };

            if (!(statm >> pages))
            {
                return 0;
            }

            const auto pageSize { sysconf(_SC_PAGESIZE) };
            return pageSize > 0 ? pages * static_cast<std::size_t>(pageSize) : 0;
        }

        /// @brief The address space the child may reach: the parent's size plus the headroom, saturating.
        static inline std::size_t limitFor(std::size_t parentSize)
        {
            if (parentSize == 0)
            {
                return 0;
            }

            const auto largest { static_cast<std::size_t>(~0UL) };
            return parentSize > largest - CHILD_MEMORY_HEADROOM ? largest : parentSize + CHILD_MEMORY_HEADROOM;
        }

        /// @brief Move a descriptor above the standard three, so redirecting those never touches it.
        static inline bool moveAboveStandard(int& descriptor)
        {
            if (descriptor > STDERR_FILENO)
            {
                return true;
            }

            const auto moved { fcntl(descriptor, F_DUPFD_CLOEXEC, STDERR_FILENO + 1) };

            if (moved < 0)
            {
                return false;
            }

            close(descriptor);
            descriptor = moved;
            return true;
        }

        /// @brief Closes a descriptor when it goes out of scope.
        class Descriptor final
        {
            public:
                explicit Descriptor(int descriptor)
                    : m_descriptor { descriptor }
                {
                }

                ~Descriptor()
                {
                    reset();
                }

                Descriptor(const Descriptor&) = delete;
                Descriptor& operator=(const Descriptor&) = delete;

                int get() const
                {
                    return m_descriptor;
                }

                void reset()
                {
                    if (m_descriptor >= 0)
                    {
                        close(m_descriptor);
                        m_descriptor = -1;
                    }
                }

            private:
                int m_descriptor;
        };

        /// @brief Owns a forked child: whatever way the scope is left, the child is killed and reaped.
        ///
        /// A child left running is a process spinning on a damaged file, and one left unreaped is a zombie,
        /// so an exception between the fork and the wait must not skip either.
        class ChildGuard final
        {
            public:
                explicit ChildGuard(pid_t child)
                    : m_child { child }
                {
                }

                ~ChildGuard()
                {
                    int status { 0 };
                    terminate(status);
                }

                ChildGuard(const ChildGuard&) = delete;
                ChildGuard& operator=(const ChildGuard&) = delete;

                /// @brief Collect the child if it has ended. @p known is false when it was reaped elsewhere.
                bool tryReap(int& status, bool& known)
                {
                    if (m_child <= 0)
                    {
                        return true;
                    }

                    const auto waited { waitpid(m_child, &status, WNOHANG) };

                    if (waited == m_child)
                    {
                        m_child = -1;
                        return true;
                    }

                    if (waited < 0 && errno != EINTR)
                    {
                        // Already reaped elsewhere, as when SIGCHLD is ignored. The reply is all there is.
                        m_child = -1;
                        known = false;
                        return true;
                    }

                    return false;
                }

                void terminate(int& status)
                {
                    if (m_child <= 0)
                    {
                        return;
                    }

                    kill(m_child, SIGKILL);

                    while (waitpid(m_child, &status, 0) < 0 && errno == EINTR)
                    {
                    }

                    m_child = -1;
                }

            private:
                pid_t m_child;
        };

        /// @brief The unprivileged identity the child takes, looked up by the parent.
        struct ChildIdentity
        {
            uid_t uid;
            gid_t gid;
        };

        /// @brief An account the read may run as: neither its user nor its primary group is root's.
        static inline bool isUnprivilegedAccount(uid_t uid, gid_t gid)
        {
            return uid != 0 && gid != 0;
        }

        /// @brief Find the identity the read runs as. Only a root process has anything to drop.
        /// @param identity Left empty for a process that is not root.
        /// @return False when the process is root and @p account is not an account it can use, with the
        ///         reason in @p error. It is looked up here, before the fork: the child must not call the
        ///         name services, which take locks and may load libraries.
        static inline bool resolveChildIdentity(const std::string& account, std::optional<ChildIdentity>& identity, std::string& error)
        {
            identity.reset();

            if (geteuid() != 0)
            {
                return true;
            }

            passwd entry;
            passwd* found { nullptr };
            std::vector<char> buffer(1024);
            int status { 0 };

            while ((status = getpwnam_r(account.c_str(), &entry, buffer.data(), buffer.size(), &found)) == ERANGE && buffer.size() < (1U << 20))
            {
                buffer.resize(buffer.size() * 2);
            }

            if (status != 0 || found == nullptr)
            {
                error = "the account '" + account + "' the read runs as does not exist, so the database was not read";
                return false;
            }

            if (!isUnprivilegedAccount(found->pw_uid, found->pw_gid))
            {
                error = "the account '" + account + "' the read runs as is not an unprivileged one, so the database was not read";
                return false;
            }

            identity = ChildIdentity { found->pw_uid, found->pw_gid };
            return true;
        }

        /// @brief Let the account the read runs as read the copy, and nothing more.
        ///
        /// The directory stays owned by this process, and is only made traversable: the account owns nothing
        /// it could rename or repopulate before the cleanup, which runs with the privileges of this process.
        /// The copy is the account's to read, and libdb opens it read only with no environment.
        static inline void grantRead(const ChildIdentity& identity, const std::filesystem::path& directory, const std::filesystem::path& file)
        {
            if (::chmod(directory.c_str(), S_IRWXU | S_IXGRP | S_IXOTH) != 0 ||
                    ::chown(file.c_str(), identity.uid, identity.gid) != 0 || ::chmod(file.c_str(), S_IRUSR) != 0)
            {
                throw std::runtime_error { "the temporary files could not be made readable by the account of the read: " + std::string { std::strerror(errno) } };
            }
        }

        /// @brief Become the unprivileged identity for good.
        /// @return False when any step failed or when root could still be regained.
        static inline bool dropPrivileges(const ChildIdentity& identity)
        {
            if (setgroups(0, nullptr) != 0 || setgid(identity.gid) != 0 || setuid(identity.uid) != 0)
            {
                return false;
            }

            uid_t real { 0 };
            uid_t effective { 0 };
            uid_t saved { 0 };
            gid_t realGroup { 0 };
            gid_t effectiveGroup { 0 };
            gid_t savedGroup { 0 };

            if (getresuid(&real, &effective, &saved) != 0 || getresgid(&realGroup, &effectiveGroup, &savedGroup) != 0 ||
                    real != identity.uid || effective != identity.uid || saved != identity.uid ||
                    realGroup != identity.gid || effectiveGroup != identity.gid || savedGroup != identity.gid)
            {
                return false;
            }

            // Root must be gone, not only hidden.
            if (setuid(0) == 0)
            {
                return false;
            }

            // Nothing this process executes can gain privileges back. A kernel older than 3.5 does not
            // know the flag; the ids are already dropped and verified, so that is not a failure.
            return prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0 || errno == EINVAL;
        }

        /// @brief What the child does before it touches the database: be an ordinary process of its own.
        /// @param limit Address space the child may reach, 0 for no limit.
        /// @param identity When set, the identity the child drops to. Failing to is fatal to the child.
        /// @return False when the limit could not be set.
        static inline bool prepareChild(pid_t parent,
                                        std::chrono::milliseconds deadline,
                                        int keep,
                                        std::size_t limit,
                                        const std::optional<ChildIdentity>& identity)
        {
            // A crash must end this process, whatever handlers the parent installed.
            for (int signalNumber = 1; signalNumber < 32; ++signalNumber)
            {
                if (signalNumber != SIGKILL && signalNumber != SIGSTOP)
                {
                    signal(signalNumber, SIG_DFL);
                }
            }

            sigset_t none;
            sigemptyset(&none);
            pthread_sigmask(SIG_SETMASK, &none, nullptr);

            // A file that crashes libdb must not leave a core the size of the parent on every scan.
            const rlimit noCore { 0, 0 };
            setrlimit(RLIMIT_CORE, &noCore);

            const auto nothing { open("/dev/null", O_RDWR) };

            if (nothing >= 0)
            {
                dup2(nothing, STDIN_FILENO);
                dup2(nothing, STDOUT_FILENO);
                dup2(nothing, STDERR_FILENO);

                if (nothing > STDERR_FILENO)
                {
                    close(nothing);
                }
            }

            // Before the drop: it lists /proc/self/fd, which the process no longer owns afterwards.
            closeInheritedDescriptors(keep);

            if (identity && !dropPrivileges(*identity))
            {
                _exit(CHILD_EXIT_PRIVILEGES);
            }

            // The parent kills a child that overruns, but a parent that dies first must not leave one
            // spinning: it goes with its parent, and at the latest a little after the deadline. Set after the
            // identity changed, since the kernel clears the signal when the credentials do.
            prctl(PR_SET_PDEATHSIG, SIGKILL);

            if (getppid() != parent)
            {
                _exit(CHILD_EXIT_ORPHANED);
            }

            alarm(static_cast<unsigned int>(deadline.count() / 1000 + CHILD_GRACE_SECONDS));

            if (limit == 0)
            {
                return false;
            }

            const rlimit memory { limit, limit };
            return setrlimit(RLIMIT_AS, &memory) == 0;
        }

        /// @brief Run @p work in a forked child and collect what it sends back, within @p deadline.
        /// @param stop Polled while waiting. True kills the child at once and fails the run.
        /// @param identity The unprivileged identity the child drops to, when the process is root.
        /// @param reply Bytes the child sent, when it ran to the end.
        /// @param failure Why it did not: timed out, crashed with a signal, exited abnormally, no reply.
        /// @param transient Set with @p failure when it says nothing about the database: the read was cancelled,
        ///        timed out, could not start or was ended from outside, so reading again can work.
        /// @param warning Set when the child ran but its memory limit could not be set.
        /// @return True when the child ran to the end and sent a reply.
        ///
        /// The child is the only place libdb touches the bytes of an image. It is killed when it takes too
        /// long and it is always reaped, so a damaged file costs the one database and never the process,
        /// a thread, or a zombie.
        ///
        /// The process is multi-threaded and the child is not an exec: it runs `work` on the copy of the
        /// calling thread alone. That is acceptable because the child takes no lock this module holds (it
        /// does not log, and touches no module state), and what it does use is made safe across fork: glibc
        /// resets its allocator locks in the child, and libdb is given a handle created in the child with no
        /// environment, so it shares nothing with the parent. A lock another thread of the parent held at the
        /// time of the fork stays locked in the child, so the child must not reach one: it converts dates by
        /// arithmetic (the time zone lock is one), parses numbers without exceptions (the unwinder takes the
        /// loader's lock) and looks no account up (the parent does). What is left is allocation, which glibc
        /// makes safe, and the error paths of libdb and of the wrapper, which format a message or throw.
        /// The tree has no fork without exec to reuse (`wpopenv` and `wm_exec` exec), so the termination
        /// signals are blocked across the fork and every handler is reset in the child, as `wpopenv` does.
        static inline bool runInChild(const std::function<std::string()>& work,
                                      std::chrono::milliseconds deadline,
                                      const std::function<bool()>& stop,
                                      const std::optional<ChildIdentity>& identity,
                                      std::string& reply,
                                      std::string& failure,
                                      bool& transient,
                                      std::string& warning)
        {
            int channel[2];

            if (pipe2(channel, O_CLOEXEC) != 0)
            {
                failure = std::string { "no pipe could be created: " } + std::strerror(errno);
                transient = true;
                return false;
            }

            if (!moveAboveStandard(channel[0]) || !moveAboveStandard(channel[1]))
            {
                failure = std::string { "no pipe could be created: " } + std::strerror(errno);
                transient = true;
                close(channel[0]);
                close(channel[1]);
                return false;
            }

            Descriptor reading { channel[0] };
            Descriptor writing { channel[1] };

            const auto limit { processSize() };

            if (limit == 0)
            {
                warning = "the memory limit of the read could not be set: the size of the process is unknown";
            }

            sigset_t blocked;
            sigset_t previous;
            sigemptyset(&blocked);

            // Every signal a handler of the process may be installed for, so that none runs in the child
            // between the fork and the moment it resets its handlers.
            const int handled[] { SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGALRM, SIGUSR1, SIGUSR2, SIGCHLD };

            for (const auto signalNumber : handled)
            {
                sigaddset(&blocked, signalNumber);
            }

            pthread_sigmask(SIG_BLOCK, &blocked, &previous);

            const auto parent { getpid() };
            const auto child { fork() };

            if (child != 0)
            {
                pthread_sigmask(SIG_SETMASK, &previous, nullptr);
            }

            if (child < 0)
            {
                failure = std::string { "no process could be created: " } + std::strerror(errno);
                transient = true;
                return false;
            }

            if (child == 0)
            {
                const auto limited { prepareChild(parent, deadline, writing.get(), limitFor(limit), identity) };

                std::string answer;
                answer += limited || limit == 0 ? LIMIT_SET : LIMIT_NOT_SET;

                try
                {
                    answer += work();
                }
                catch (...)
                {
                    _exit(CHILD_EXIT_EXCEPTION);
                }

                std::size_t written { 0 };

                while (written < answer.size())
                {
                    const auto count { write(writing.get(), answer.data() + written, answer.size() - written) };

                    if (count < 0 && errno == EINTR)
                    {
                        continue;
                    }

                    if (count <= 0)
                    {
                        _exit(CHILD_EXIT_REPLY);
                    }

                    written += static_cast<std::size_t>(count);
                }

                _exit(0);
            }

            writing.reset();
            ChildGuard guard { child };

            const auto end { std::chrono::steady_clock::now() + deadline };
            const auto remaining = [&end]()
            {
                return std::chrono::duration_cast<std::chrono::milliseconds>(end - std::chrono::steady_clock::now());
            };

            bool timedOut { false };
            bool cancelled { false };
            bool tooLarge { false };
            bool readFailed { false };
            std::string received;
            char buffer[65536];

            while (true)
            {
                if (stop && stop())
                {
                    cancelled = true;
                    break;
                }

                const auto left { remaining() };

                if (left.count() <= 0)
                {
                    timedOut = true;
                    break;
                }

                pollfd waiting { reading.get(), POLLIN, 0 };
                const auto ready { poll(&waiting, 1, static_cast<int>(std::min<long long>(left.count(), STOP_CHECK_INTERVAL))) };

                if (ready < 0 && errno != EINTR)
                {
                    readFailed = true;
                    break;
                }

                if (ready <= 0)
                {
                    continue;
                }

                const auto count { read(reading.get(), buffer, sizeof(buffer)) };

                if (count < 0 && (errno == EINTR || errno == EAGAIN))
                {
                    continue;
                }

                if (count < 0)
                {
                    readFailed = true;
                    break;
                }

                if (count == 0)
                {
                    break;
                }

                if (received.size() + static_cast<std::size_t>(count) > BERKELEY_REPLY_LIMIT)
                {
                    tooLarge = true;
                    break;
                }

                received.append(buffer, static_cast<std::size_t>(count));
            }

            reading.reset();

            // The child closes its end when it ends, but one that closed it early and kept running must
            // not be waited for past the deadline either.
            int status { 0 };
            bool known { true };
            bool reaped { false };

            while (!reaped && !timedOut && !cancelled && !tooLarge && !readFailed)
            {
                reaped = guard.tryReap(status, known);

                if (reaped)
                {
                    break;
                }

                if (stop && stop())
                {
                    cancelled = true;
                }
                else if (remaining().count() <= 0)
                {
                    timedOut = true;
                }
                else
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds { 1 });
                }
            }

            if (!reaped)
            {
                guard.terminate(status);
            }

            if (cancelled)
            {
                failure = "the read was cancelled by a stop request";
                transient = true;
            }
            else if (timedOut)
            {
                failure = "the read timed out after " + describeDuration(deadline);
                transient = true;
            }
            else if (tooLarge)
            {
                failure = "the reply was larger than the supported size";
            }
            else if (readFailed)
            {
                failure = "the reply could not be read";
                transient = true;
            }
            else if (known && WIFSIGNALED(status))
            {
                failure = "the read crashed with signal " + std::to_string(WTERMSIG(status));

                // A kill from outside (the out-of-memory killer) or the child's own alarm is the load of the
                // machine. A fault of the file is a crash of the child's own: segmentation, bus error, abort.
                transient = WTERMSIG(status) == SIGKILL || WTERMSIG(status) == SIGALRM;
            }
            else if (known && WIFEXITED(status) && WEXITSTATUS(status) == CHILD_EXIT_PRIVILEGES)
            {
                failure = "the privileges of the read could not be dropped";
                transient = true;
            }
            else if (known && WIFEXITED(status) && WEXITSTATUS(status) == CHILD_EXIT_UNREADABLE)
            {
                failure = "the account of the read could not open the copy of the database";
                transient = true;
            }
            else if (known && WIFEXITED(status) && WEXITSTATUS(status) == CHILD_EXIT_REPLY)
            {
                failure = "the read exited with status " + std::to_string(WEXITSTATUS(status));
                transient = true;
            }
            else if (known && WIFEXITED(status) && WEXITSTATUS(status) != 0)
            {
                failure = "the read exited with status " + std::to_string(WEXITSTATUS(status));
            }
            else if (received.empty())
            {
                // Nothing came back, not even the flag the child sends first.
                reply.clear();
                return true;
            }
            else
            {
                if (received.front() == LIMIT_NOT_SET && warning.empty())
                {
                    warning = "the memory limit of the read could not be set";
                }

                reply = received.substr(1);
                return true;
            }

            return false;
        }
#endif
    } // namespace detail

    /// @brief dpkg `status`: RFC822-like stanzas separated by a blank line.
    /// @param content Full content of the file.
    /// @param dbPath Stored on every package.
    static inline std::vector<Package> parseDpkg(const std::string& content, const std::string& dbPath)
    {
        std::vector<Package> packages;

        for (const auto& stanza : detail::splitStanzas(content))
        {
            Package package;

            if (detail::dpkgPackage(detail::dpkgFields(stanza), dbPath, package))
            {
                packages.push_back(std::move(package));
            }
        }

        return packages;
    }

    /// @brief One file of the dpkg `status.d` directory: a single package, blank lines included.
    ///
    /// dpkg itself never ran for these packages, so the stanza usually has no `Status` line.
    /// Every file in the directory is an installed package by construction, so a missing one
    /// is read as installed. A file that states another status is not installed.
    static inline std::vector<Package> parseDpkgStatusD(const std::string& content, const std::string& dbPath)
    {
        auto fields { detail::dpkgFields(content) };
        fields.emplace("Status", "install ok installed");

        std::vector<Package> packages;
        Package package;

        if (detail::dpkgPackage(fields, dbPath, package))
        {
            packages.push_back(std::move(package));
        }

        return packages;
    }

    /// @brief apk `installed`: stanzas of single-letter keys.
    ///
    /// P name, V version, A architecture, m maintainer, T description, o origin and I
    /// installed size in bytes. The other keys are not inventory fields.
    static inline std::vector<Package> parseApk(const std::string& content, const std::string& dbPath)
    {
        std::vector<Package> packages;

        for (const auto& stanza : detail::splitStanzas(content))
        {
            std::map<char, std::string> fields;
            std::istringstream stream { stanza };
            std::string line;

            while (std::getline(stream, line))
            {
                if (line.size() < 2 || line[1] != ':')
                {
                    continue;
                }

                fields[line[0]] = detail::trim(line.substr(2));
            }

            const auto value = [&fields](const char key)
            {
                const auto entry { fields.find(key) };

                if (entry == fields.end())
                {
                    return std::string {};
                }

                return entry->second;
            };

            if (value('P').empty())
            {
                continue;
            }

            Package package;
            package.name = value('P');
            package.version = value('V');
            package.architecture = value('A');
            package.type = FORMAT_APK;
            package.vendor = value('m');
            package.description = value('T');
            package.source = value('o');
            package.size = detail::parseSize(value('I'), 1);
            package.packageDbPath = dbPath;

            packages.push_back(std::move(package));
        }

        return packages;
    }

    /// @brief rpm sqlite (`rpmdb.sqlite`) or ndb (`Packages.db`), read from memory.
    ///
    /// The two hold the same package headers and differ in how they store them, so one
    /// function reads both and picks the format from the content, not from the path. A
    /// database rpm left in write-ahead log mode is read as of its last checkpoint.
    /// @param error When given, set for a file that is neither: it holds something, and no packages were read.
    static inline std::vector<Package> parseRpm(const std::string& content, const std::string& dbPath, std::string* error = nullptr)
    {
        std::vector<Package> packages;

        const auto collect
        {
            [&packages, &dbPath](const uint8_t* blob, std::size_t size)
            {
                detail::collectRpmBlob(blob, size, dbPath, packages);
            }
        };

        if (!RpmDbSqlite::readFromMemory(content.data(), content.size(), collect) &&
                !RpmDbNdb::readFromMemory(content.data(), content.size(), collect) &&
                !content.empty() && error != nullptr)
        {
            *error = "the rpm database could not be read as SQLite or NDB";
        }

        return packages;
    }

    /// @brief What reading one Berkeley DB file gave.
    struct BerkeleyDbResult
    {
        std::vector<Package> packages;
        std::string error;   ///< Empty when the database was read. Otherwise why it was not.
        bool transient {false}; ///< As DatabaseReport::transient.
        std::string warning; ///< Something worth a log line that did not stop the read.
    };

    /// @brief rpm Berkeley DB (`Packages`, rpm before 4.16).
    /// @param options Deadline, stop request and child entry point, left alone except by tests.
    ///
    /// libdb opens by path, so the bytes are written into a private directory, and the directory is
    /// removed on every path. The file is read with the hardened wrapper the host inventory uses, in a
    /// child process: libdb hangs or crashes on a damaged file, and that must cost this database only.
    /// A child that runs too long, or is cancelled, is killed, one that crashes or answers nonsense is
    /// reported in `error`, and no packages are returned for it. `transient` tells a failure of the
    /// machine (timeout, cancel, no process or file, killed from outside) from one of the file.
    /// When the process is root the child runs as `options.account`, and when that account does not exist
    /// the child is not started and `error` says so. The child gets a memory limit; when it
    /// cannot be set the read goes on and `warning` says so. On a platform without libdb, nothing is
    /// read and `error` says so.
    static inline BerkeleyDbResult readRpmBerkeleyDb(const std::string& content,
                                                     const std::string& dbPath,
                                                     const BerkeleyDbOptions& options = {})
    {
        BerkeleyDbResult result;

#if defined(__linux__)

        try
        {
            if (!detail::isBerkeleyHashDatabase(content))
            {
                result.error = "the file is not a Berkeley DB hash database";
                return result;
            }

            std::optional<detail::ChildIdentity> identity;

            if (!detail::resolveChildIdentity(options.account, identity, result.error))
            {
                result.transient = true;
                return result;
            }

            // Declared first so it is destroyed last: the child is gone before its file is.
            detail::PrivateDirectory directory;
            const auto file { (directory.path() / "Packages").string() };

            {
                std::ofstream output { file, std::ios::binary | std::ios::trunc };
                output.write(content.data(), static_cast<std::streamsize>(content.size()));
                output.close();

                if (!output)
                {
                    throw std::runtime_error { "the database could not be written to the temporary directory" };
                }
            }

            if (identity)
            {
                detail::grantRead(*identity, directory.path(), file);
            }

            const auto work { options.child ? options.child : std::function<std::string(const std::string&, const std::string&)> { detail::readBerkeleyDbFile } };
            std::string reply;

            // An account that cannot reach the copy (a temporary directory under a path only root enters) says
            // nothing about the database, and must not be read as a damaged one.
            const auto checkAccess { identity.has_value() };

            const auto ran { detail::runInChild([&work, &file, &dbPath, checkAccess]()
            {
                if (checkAccess && access(file.c_str(), R_OK) != 0)
                {
                    _exit(detail::CHILD_EXIT_UNREADABLE);
                }

                return work(file, dbPath);
            }, options.deadline, options.stop, identity, reply, result.error, result.transient, result.warning) };

            if (!ran)
            {
                return result;
            }

            std::vector<Package> read;
            std::string reported;

            if (!detail::parseReply(reply, read, reported))
            {
                result.error = "the reply of the read was malformed";
            }
            else if (!reported.empty())
            {
                result.error = reported;
            }
            else
            {
                result.packages = std::move(read);
            }
        }
        catch (const std::exception& exception)
        {
            // No directory, no copy, no memory: the machine, not the file.
            result.error = exception.what();
            result.transient = true;
        }

#else
        static_cast<void>(content);
        static_cast<void>(dbPath);
        static_cast<void>(options);
        result.error = BERKELEY_DB_UNSUPPORTED_ERROR;
#endif

        return result;
    }

    /// @brief As readRpmBerkeleyDb, for a caller that only wants the packages and the error.
    static inline std::vector<Package> parseRpmBerkeleyDb(const std::string& content,
                                                          const std::string& dbPath,
                                                          std::string& error,
                                                          const BerkeleyDbOptions& options = {})
    {
        auto result { readRpmBerkeleyDb(content, dbPath, options) };
        error = std::move(result.error);
        return std::move(result.packages);
    }

    /// @brief Read the package databases among @p files.
    ///
    /// For each format the first database present, in the order of databaseLocations(), is
    /// read, and the others are reported as skipped. dpkg `status` and `status.d` are both
    /// read and merged, since a distroless image keeps its base packages in `status.d` and a
    /// later layer can add a `status` file next to them: a package in both, by name and
    /// architecture, is the one `status` describes. Different formats are read independently,
    /// so an image that carries two of them reports both.
    static inline Result read(const Files& files, const BerkeleyDbOptions& options = {})
    {
        Result result;

        const auto add = [&result](const std::string & path, std::vector<Package>&& packages, const std::string & error, const std::string & warning, bool transient = false)
        {
            DatabaseReport report;
            report.path = path;
            report.packages = packages.size();
            report.error = error;
            report.transient = transient;
            report.warning = warning;

            result.databases.push_back(std::move(report));
            result.packages.insert(result.packages.end(),
                                   std::make_move_iterator(packages.begin()),
                                   std::make_move_iterator(packages.end()));
        };

        const auto skip = [&result](const std::string & path)
        {
            DatabaseReport report;
            report.path = path;
            report.skipped = true;
            result.databases.push_back(std::move(report));
        };

        // dpkg.
        std::vector<std::string> statusD;

        for (const auto& [path, content] : files)
        {
            if (isStatusDEntry(path))
            {
                statusD.push_back(path);
            }
        }

        // Every stanza of `status` is the word on its package, whatever its state: one that says it was
        // removed is not undone by an entry of status.d. Packages are the same by name and architecture, and
        // by name alone when either side states no architecture.
        std::multimap<std::string, std::string> inStatus;

        if (const auto status { files.find(DPKG_STATUS_PATH) }; status != files.end())
        {
            for (const auto& stanza : detail::splitStanzas(status->second))
            {
                const auto fields { detail::dpkgFields(stanza) };
                const auto name { detail::field(fields, "Package") };

                if (!name.empty())
                {
                    inStatus.emplace(name, detail::field(fields, "Architecture"));
                }
            }

            add(status->first, parseDpkg(status->second, status->first), {}, {});
        }

        if (!statusD.empty())
        {
            std::vector<Package> packages;

            for (const auto& path : statusD)
            {
                auto entry { parseDpkgStatusD(files.at(path), path) };

                for (auto& package : entry)
                {
                    const auto [first, last] { inStatus.equal_range(package.name) };
                    const auto shadowed { std::any_of(first, last, [&package](const auto & known)
                    {
                        return known.second == package.architecture || known.second.empty() || package.architecture.empty();
                    }) };

                    if (!shadowed)
                    {
                        packages.push_back(std::move(package));
                    }
                }
            }

            add(DPKG_STATUS_D_DIRECTORY, std::move(packages), {}, {});
        }

        // apk and rpm.
        std::vector<std::string> formatsRead;

        for (const auto& location : databaseLocations())
        {
            const std::string format { location.format };

            if (format == FORMAT_DPKG)
            {
                continue;
            }

            const auto database { files.find(location.path) };

            if (database == files.end())
            {
                continue;
            }

            if (std::find(formatsRead.begin(), formatsRead.end(), format) != formatsRead.end())
            {
                skip(database->first);
                continue;
            }

            formatsRead.push_back(format);

            if (format == FORMAT_APK)
            {
                add(database->first, parseApk(database->second, database->first), {}, {});
                continue;
            }

            if (location.berkeleyDb)
            {
                auto read { readRpmBerkeleyDb(database->second, database->first, options) };
                add(database->first, std::move(read.packages), read.error, read.warning, read.transient);
                continue;
            }

            std::string error;
            auto packages { parseRpm(database->second, database->first, &error) };
            add(database->first, std::move(packages), error, {});
        }

        return result;
    }
} // namespace PackageDb

#endif // _PACKAGE_DB_PARSER_HPP
