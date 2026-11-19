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
#include "timeHelper.h"

#if defined(__linux__)
#include "berkeleyDbWrapper.h"

#include <fcntl.h>
#include <poll.h>
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
#endif

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <random>
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

    /// How long one Berkeley DB file may take to read. libdb is given the bytes of a file an image
    /// carries, and a damaged one can send it into an endless loop. Reading a real database of a few
    /// hundred packages takes milliseconds, so the limit only ever applies to a file that is not one.
    constexpr std::chrono::milliseconds BERKELEY_DB_READ_DEADLINE { std::chrono::seconds { 30 } };

    /// @brief Run the Berkeley DB read differently, which is how the tests make it fast or fail.
    struct BerkeleyDbOptions
    {
        std::chrono::milliseconds deadline { BERKELEY_DB_READ_DEADLINE };

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

        /// @brief Parse a size field and scale it by @p unit.
        /// @return 0 for anything that is not a number, and for a value that overflows once scaled.
        static inline long long parseSize(const std::string& value, long long unit)
        {
            try
            {
                const auto number { std::stoll(value) };

                if (number > LARGEST_SIZE / unit || number < (-LARGEST_SIZE - 1) / unit)
                {
                    return 0;
                }

                return number * unit;
            }
            catch (const std::exception&)
            {
                return 0;
            }
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

        /// @brief The install date as ISO 8601, empty when the database records none.
        static inline std::string rpmInstallDate(const std::string& timestamp)
        {
            try
            {
                return Utils::rawTimestampToISO8601(static_cast<uint32_t>(std::stoll(timestamp)));
            }
            catch (const std::exception&)
            {
                return {};
            }
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
                while (database.getRow(key, data) == 0)
                {
                    collectRpmBlob(static_cast<const uint8_t*>(data.data), data.size, dbPath, packages);
                }
            }
            catch (const std::exception& exception)
            {
                return serializeError(exception.what());
            }

            return serializePackages(packages);
        }

        /// @brief Close every descriptor the process inherited except 0, 1, 2 and @p keep.
        static inline void closeInheritedDescriptors(int keep)
        {
            constexpr unsigned int LAST { ~0U };
            const auto first { static_cast<unsigned int>(keep) };
            bool closed { true };

#if defined(SYS_close_range)

            if (keep > 3)
            {
                closed = syscall(SYS_close_range, 3U, first - 1, 0U) == 0;
            }

            closed = closed && syscall(SYS_close_range, first + 1, LAST, 0U) == 0;
#else
            closed = false;
#endif

            if (!closed)
            {
                const auto limit { sysconf(_SC_OPEN_MAX) };

                for (int descriptor = 3; descriptor < (limit > 0 && limit < 4096 ? limit : 4096); ++descriptor)
                {
                    if (descriptor != keep)
                    {
                        close(descriptor);
                    }
                }
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

        /// @brief What the child does before it touches the database: be an ordinary process of its own.
        /// @param limit Address space the child may reach, 0 for no limit.
        /// @return False when the limit could not be set.
        static inline bool prepareChild(pid_t parent, std::chrono::milliseconds deadline, int keep, std::size_t limit)
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

            // The parent kills a child that overruns, but a parent that dies first must not leave one
            // spinning: it goes with its parent, and at the latest a little after the deadline.
            prctl(PR_SET_PDEATHSIG, SIGKILL);

            if (getppid() != parent)
            {
                _exit(4);
            }

            alarm(static_cast<unsigned int>(deadline.count() / 1000 + CHILD_GRACE_SECONDS));

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

            closeInheritedDescriptors(keep);

            if (limit == 0)
            {
                return false;
            }

            const rlimit memory { limit, limit };
            return setrlimit(RLIMIT_AS, &memory) == 0;
        }

        /// @brief Run @p work in a forked child and collect what it sends back, within @p deadline.
        /// @param stop Polled while waiting. True kills the child at once and fails the run.
        /// @param reply Bytes the child sent, when it ran to the end.
        /// @param failure Why it did not: timed out, crashed with a signal, exited abnormally, no reply.
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
        /// time of the fork stays locked in the child, so the child must never reach one; it reaches none.
        /// The tree has no fork without exec to reuse (`wpopenv` and `wm_exec` exec), so the termination
        /// signals are blocked across the fork and every handler is reset in the child, as `wpopenv` does.
        static inline bool runInChild(const std::function<std::string()>& work,
                                      std::chrono::milliseconds deadline,
                                      const std::function<bool()>& stop,
                                      std::string& reply,
                                      std::string& failure,
                                      std::string& warning)
        {
            int channel[2];

            if (pipe2(channel, O_CLOEXEC) != 0)
            {
                failure = std::string { "no pipe could be created: " } + std::strerror(errno);
                return false;
            }

            if (!moveAboveStandard(channel[0]) || !moveAboveStandard(channel[1]))
            {
                failure = std::string { "no pipe could be created: " } + std::strerror(errno);
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
                return false;
            }

            if (child == 0)
            {
                const auto limited { prepareChild(parent, deadline, writing.get(), limitFor(limit)) };

                std::string answer;
                answer += limited || limit == 0 ? LIMIT_SET : LIMIT_NOT_SET;

                try
                {
                    answer += work();
                }
                catch (...)
                {
                    _exit(2);
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
                        _exit(3);
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
            }
            else if (timedOut)
            {
                failure = "the read timed out after " + describeDuration(deadline);
            }
            else if (tooLarge)
            {
                failure = "the reply was larger than the supported size";
            }
            else if (readFailed)
            {
                failure = "the reply could not be read";
            }
            else if (known && WIFSIGNALED(status))
            {
                failure = "the read crashed with signal " + std::to_string(WTERMSIG(status));
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
    static inline std::vector<Package> parseRpm(const std::string& content, const std::string& dbPath)
    {
        std::vector<Package> packages;

        const auto collect
        {
            [&packages, &dbPath](const uint8_t* blob, std::size_t size)
            {
                detail::collectRpmBlob(blob, size, dbPath, packages);
            }
        };

        if (!RpmDbSqlite::readFromMemory(content.data(), content.size(), collect))
        {
            RpmDbNdb::readFromMemory(content.data(), content.size(), collect);
        }

        return packages;
    }

    /// @brief What reading one Berkeley DB file gave.
    struct BerkeleyDbResult
    {
        std::vector<Package> packages;
        std::string error;   ///< Empty when the database was read. Otherwise why it was not.
        std::string warning; ///< Something worth a log line that did not stop the read.
    };

    /// @brief rpm Berkeley DB (`Packages`, rpm before 4.16).
    /// @param options Deadline, stop request and child entry point, left alone except by tests.
    ///
    /// libdb opens by path, so the bytes are written into a private directory, and the directory is
    /// removed on every path. The file is read with the hardened wrapper the host inventory uses, in a
    /// child process: libdb hangs or crashes on a damaged file, and that must cost this database only.
    /// A child that runs too long, or is cancelled, is killed, one that crashes or answers nonsense is
    /// reported in `error`, and no packages are returned for it. The child gets a memory limit; when it
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

            const auto work { options.child ? options.child : std::function<std::string(const std::string&, const std::string&)> { detail::readBerkeleyDbFile } };
            std::string reply;

            const auto ran { detail::runInChild([&work, &file, &dbPath]()
            {
                return work(file, dbPath);
            }, options.deadline, options.stop, reply, result.error, result.warning) };

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
            result.error = exception.what();
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
    /// read, and the others are reported as skipped. dpkg `status.d` is read only when
    /// `status` is absent, so a Debian image and a distroless one are each described by the
    /// file that describes them. Different formats are read independently, so an image that
    /// carries two of them reports both.
    static inline Result read(const Files& files, const BerkeleyDbOptions& options = {})
    {
        Result result;

        const auto add = [&result](const std::string & path, std::vector<Package>&& packages, const std::string & error, const std::string & warning)
        {
            DatabaseReport report;
            report.path = path;
            report.packages = packages.size();
            report.error = error;
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

        if (const auto status { files.find(DPKG_STATUS_PATH) }; status != files.end())
        {
            add(status->first, parseDpkg(status->second, status->first), {}, {});

            if (!statusD.empty())
            {
                skip(DPKG_STATUS_D_DIRECTORY);
            }
        }
        else if (!statusD.empty())
        {
            std::vector<Package> packages;

            for (const auto& path : statusD)
            {
                auto entry { parseDpkgStatusD(files.at(path), path) };
                packages.insert(packages.end(), std::make_move_iterator(entry.begin()), std::make_move_iterator(entry.end()));
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
                add(database->first, std::move(read.packages), read.error, read.warning);
                continue;
            }

            add(database->first, parseRpm(database->second, database->first), {}, {});
        }

        return result;
    }
} // namespace PackageDb

#endif // _PACKAGE_DB_PARSER_HPP
