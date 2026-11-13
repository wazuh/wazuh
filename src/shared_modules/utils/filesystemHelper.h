/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * October 23, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _FILESYSTEM_HELPER_H
#define _FILESYSTEM_HELPER_H

#include <string>
#include <iostream>
#include <fstream>
#include <cstdio>
#include <memory>
#include <sstream>
#include <sys/types.h>
#include <sys/stat.h>
#include <vector>
#include <dirent.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <libgen.h>
#include "stringHelper.h"

#ifdef __linux__
#include <chrono>
#include <fcntl.h>
#include <functional>
#include <mutex>
#include <sys/vfs.h>
#include <unistd.h>
#include <unordered_map>
#endif

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

#ifndef PATH_MAX
    #define PATH_MAX 4096
#endif

namespace Utils
{
    static bool existsDir(const std::string& path)
    {
        struct stat info {};
        return !stat(path.c_str(), &info) && (info.st_mode & S_IFDIR);
    }
    static bool existsRegular(const std::string& path)
    {
        struct stat info {};
        return !stat(path.c_str(), &info) && (info.st_mode & S_IFREG);
    }
#ifndef WIN32
    static bool existsSocket(const std::string& path)
    {
        struct stat info {};
        return !stat(path.c_str(), &info) && ((info.st_mode & S_IFMT) == S_IFSOCK);
    }
#endif

#ifdef __linux__
    /// @brief Reports the file system of an open descriptor, as fstatfs() does.
    using FileSystemStatusFunction = int (*)(int, struct statfs*);

    /// @brief isUnmountedAutomountPoint() with the fstatfs() call given, so tests can report any
    /// file system type for a real path.
    ///
    /// @param path Path to check.
    /// @param fileSystemStatus Called with the path's O_PATH descriptor, as fstatfs().
    /// @return true if the path resolves to an autofs trigger, false otherwise or on error.
    static bool isUnmountedAutomountPoint(const std::string& path, FileSystemStatusFunction fileSystemStatus)
    {
        // The agent packages are built against C library headers that predate O_PATH (and, for the
        // legacy ones, O_CLOEXEC), so fall back to the kernel value, which is the same on every
        // architecture the agent is built for (x86, ARM, PowerPC).
        // Kernels older than 2.6.39 ignore O_PATH and open the path for reading, which mounts it,
        // so it is reported as mounted, as before; O_NONBLOCK and O_NOCTTY keep that open from
        // waiting on a FIFO or taking a terminal, and are ignored along with O_PATH. Kernels that
        // reject fstatfs() on an O_PATH descriptor (before 3.12, unless backported, as in RHEL 7)
        // also report the path as mounted.
#ifdef O_PATH
        constexpr auto OPEN_PATH_ONLY {O_PATH};
#else
        constexpr auto OPEN_PATH_ONLY {010000000};
#endif
#ifdef O_CLOEXEC
        constexpr auto OPEN_CLOSE_ON_EXEC {O_CLOEXEC};
#else
        constexpr auto OPEN_CLOSE_ON_EXEC {0};
#endif
        constexpr auto AUTOFS_SUPER_MAGIC_VALUE {0x0187};
        // No O_DIRECTORY: it makes the open trigger the automount.
        const auto fd {::open(path.c_str(), OPEN_PATH_ONLY | OPEN_CLOSE_ON_EXEC | O_NONBLOCK | O_NOCTTY)};

        if (fd < 0)
        {
            return false;
        }

        struct statfs info {};

        const auto result {fileSystemStatus(fd, &info)};

        ::close(fd);

        return result == 0 && info.f_type == AUTOFS_SUPER_MAGIC_VALUE;
    }

    /// @brief Reuses the answers of isUnmountedAutomountPoint() for a minute, so the collectors that
    /// look at the same home directories in one scan (PyPI, npm, Chrome, Firefox) ask the file system
    /// once per home: on an NFS home, each fstatfs() is a call to the server.
    class AutomountCheckCache final
    {
        public:
            using Clock = std::chrono::steady_clock;

            /// @brief How long an answer is reused. A home mounted within it is skipped until it
            /// passes, and one that expires within it is looked into, and mounted again, once.
            static constexpr std::chrono::seconds ttl()
            {
                return std::chrono::seconds {60};
            }

            /// @brief Answer for a path: the cached one if it is younger than ttl(), otherwise the
            /// one probe gives, which is then cached.
            static bool check(const std::string& path,
                              const std::function<bool(const std::string&)>& probe,
                              const Clock::time_point now = Clock::now())
            {
                auto& state {instance()};

                {
                    std::lock_guard<std::mutex> lock {state.mutex};
                    const auto it {state.entries.find(path)};

                    if (it != state.entries.end() && now - it->second.checkedAt < ttl())
                    {
                        return it->second.unmounted;
                    }
                }

                // Asked without the lock, so a server that does not answer only holds up this caller
                const auto unmounted {probe(path)};

                std::lock_guard<std::mutex> lock {state.mutex};

                if (now - state.prunedAt >= ttl())
                {
                    for (auto it {state.entries.begin()}; it != state.entries.end();)
                    {
                        it = now - it->second.checkedAt >= ttl() ? state.entries.erase(it) : std::next(it);
                    }

                    state.prunedAt = now;
                }

                state.entries[path] = Entry {unmounted, now};
                return unmounted;
            }

            /// @brief Forgets every answer.
            static void clear()
            {
                auto& state {instance()};
                std::lock_guard<std::mutex> lock {state.mutex};
                state.entries.clear();
            }

        private:
            struct Entry
            {
                bool unmounted;
                Clock::time_point checkedAt;
            };

            struct State
            {
                std::mutex mutex;
                std::unordered_map<std::string, Entry> entries;
                Clock::time_point prunedAt;
            };

            // Shared by every collector built into the same library
            static State& instance()
            {
                static State state;
                return state;
            }
    };
#endif

    /// @brief Tells whether a path is an automount point whose filesystem is not mounted yet.
    ///
    /// Looking inside such a path makes the automounter mount it, so callers walking many entries
    /// (e.g. every home directory under an automounted /home) can skip them instead. For an entry
    /// listed by its parent directory, the check does not mount it: opening with O_PATH does not
    /// trigger the automount of the last component, and the filesystem mounted there, once it is,
    /// is no longer autofs. Symbolic links are followed, so the components of a link's target are
    /// resolved (and mounted, if they are automount points) as any access through the link would.
    ///
    /// The answer for a path is reused for a minute (AutomountCheckCache).
    ///
    /// @param path Path to check.
    /// @return true if the path resolves to an autofs trigger, false otherwise or on error.
    static bool isUnmountedAutomountPoint(const std::string& path)
    {
#ifdef __linux__
        return AutomountCheckCache::check(path, [](const std::string & checkedPath)
        {
            return isUnmountedAutomountPoint(checkedPath, ::fstatfs);
        });
#else
        (void)path;

        return false;

#endif
    }
    struct DirSmartDeleter
    {
        void operator()(DIR* dir)
        {
            closedir(dir);
        }
    };

    static std::vector<std::string> enumerateDir(const std::string& path)
    {
        std::vector<std::string> ret;
        std::unique_ptr<DIR, DirSmartDeleter> spDir{opendir(path.c_str())};

        if (spDir)
        {
            auto entry{readdir(spDir.get())};

            while (entry)
            {
                ret.push_back(entry->d_name);
                entry = readdir(spDir.get());
            }
        }

        return ret;
    }

    static std::string getFileContent(const std::string& filePath)
    {
        std::stringstream content;
        std::ifstream file { filePath, std::ios_base::in };

        if (file.is_open())
        {
            content << file.rdbuf();
        }

        return content.str();
    }

    static std::vector<char> getBinaryContent(const std::string& filePath)
    {
        auto size { 0 };
        std::unique_ptr<char[]> spBuffer;
        std::ifstream file { filePath, std::ios_base::binary };

        if (file.is_open())
        {
            // Get pointer to associated buffer object
            auto buffer { file.rdbuf() };

            if (nullptr != buffer)
            {
                // Get file size using buffer's members
                size = buffer->pubseekoff(0, file.end, file.in);
                buffer->pubseekpos(0, file.in);
                // Allocate memory to contain file data
                spBuffer = std::make_unique<char[]>(size);
                // Get file data
                buffer->sgetn(spBuffer.get(), size);
            }
        }

        return std::vector<char> {spBuffer.get(), spBuffer.get() + size};
    }

    static std::string resolvePath(const std::string& baseFile, const std::string& relativePath)
    {
        char baseCopy[PATH_MAX];
        strncpy(baseCopy, baseFile.c_str(), sizeof(baseCopy));
        baseCopy[sizeof(baseCopy) - 1] = '\0';

        std::string dir(dirname(baseCopy));

        if (!dir.empty() && dir.back() != '/')
        {
            dir += '/';
        }

        return dir + relativePath;
    }

    static std::string getFilename(const std::string& path)
    {
        const auto pos = path.find_last_of("/\\");
        if (pos == std::string::npos)
        {
            return path;
        }
        return path.substr(pos + 1);
    }

    static std::string getFileExtension(const std::string& path)
    {
        const std::string fileName = getFilename(path);
        return "." + split(fileName, '.').back();
    }

    static std::string getParentPath(const std::string& path)
    {
        char baseCopy[PATH_MAX] = {'\0'};
        strncpy(baseCopy, path.c_str(), sizeof(baseCopy) - 1);

        std::string parentDir(dirname(baseCopy));
        return parentDir;
    }

    static bool isAbsolutePath(const std::string& path)
    {
        if (path.empty()) return false;

    #ifdef _WIN32
        // Absolute if starts with drive letter (e.g., C:\) or UNC path (\\server\share)
        return (path.size() >= 2 && std::isalpha(path[0]) && path[1] == ':') ||
              (path.size() >= 2 && path[0] == '\\' && path[1] == '\\');
    #else
        // Unix absolute path starts with '/'
        return path[0] == '/';
    #endif
    }

    static std::string joinPaths(const std::string& base, const std::string& relative)
    {
        if (base.empty()) return relative;
        if (relative.empty()) return base;

#ifdef _WIN32
        const char separator = '\\';
        const char altSeparator = '/';
#else
        const char separator = '/';
        const char altSeparator = '\\';
#endif

        // Normalize separators in relative path to use the platform separator
        std::string normalizedRelative = relative;
        std::replace(normalizedRelative.begin(), normalizedRelative.end(), altSeparator, separator);

        // Remove leading separator from relative if present
        size_t relativeStart = 0;
        while (relativeStart < normalizedRelative.length() && normalizedRelative[relativeStart] == separator)
        {
            ++relativeStart;
        }

        // Remove trailing separator from base if present
        std::string normalizedBase = base;
        while (!normalizedBase.empty() && normalizedBase.back() == separator)
        {
            normalizedBase.pop_back();
        }

        // If base is now empty (was only separators), return relative
        if (normalizedBase.empty())
        {
            return relativeStart < normalizedRelative.length()
                ? normalizedRelative.substr(relativeStart)
                : std::move(normalizedRelative);
        }

        // Join with a single separator
        return normalizedBase + separator + normalizedRelative.substr(relativeStart);
    }

    static std::string removePrefix(const std::string& fullPath, const std::string& prefix)
    {
        if (fullPath.compare(0, prefix.size(), prefix) == 0)
        {
            std::string result = fullPath.substr(prefix.size());
            if (!result.empty() && result[0] == '/')
            {
                result.erase(0, 1); // remove leading slash
            }
            return result;
        }
        return fullPath; // prefix not found, return original
    }
}

#pragma GCC diagnostic pop

#endif // _FILESYSTEM_HELPER_H
