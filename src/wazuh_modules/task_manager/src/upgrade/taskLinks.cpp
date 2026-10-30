/*
 * Wazuh task manager module
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "taskLinks.hpp"

#include "taskManagerLog.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <memory>
#include <regex>
#include <stdexcept>
#include <unordered_map>
#include <utility>
#include <vector>

namespace
{
    using namespace task_manager;

    /// @brief No trailing slash: with one, open() resolves a symlink even under O_NOFOLLOW.
    constexpr const char* TASKS_DIR {"tasks"};
    constexpr const char* TASK_TYPE {"remote_upgrade"};
    constexpr const char* TASK_FILE_SUFFIX {".wpk"};
    constexpr const char* TMP_SUFFIX {".tmp"};
    constexpr std::size_t COPY_BUFFER_SIZE {64 * 1024};

    class Fd final
    {
    public:
        explicit Fd(const int fd = -1)
            : m_fd {fd}
        {
        }

        ~Fd()
        {
            reset();
        }

        Fd(const Fd&) = delete;
        Fd& operator=(const Fd&) = delete;

        Fd& operator=(Fd&& other) noexcept
        {
            if (this != &other)
            {
                reset();
                m_fd = other.release();
            }
            return *this;
        }

        int get() const
        {
            return m_fd;
        }

        explicit operator bool() const
        {
            return m_fd >= 0;
        }

        int release()
        {
            return std::exchange(m_fd, -1);
        }

        /// @return 0, or the errno of a failed close().
        int reset()
        {
            int error {0};
            if (m_fd >= 0 && ::close(m_fd) != 0)
            {
                error = errno;
            }
            m_fd = -1;
            return error;
        }

    private:
        int m_fd;
    };

    bool isTaskFileName(const std::string& name)
    {
        static const std::regex pattern {"^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}\\.wpk$"};
        return std::regex_match(name, pattern);
    }

    bool isTemporaryName(const std::string& name)
    {
        const std::string suffix {TMP_SUFFIX};
        return name.size() > suffix.size() && name.front() == '.' &&
               name.compare(name.size() - suffix.size(), suffix.size(), suffix) == 0;
    }

    bool linkRefused(const int error)
    {
        return error == EPERM || error == EMLINK || error == EXDEV;
    }

    /// @return 0, or the errno of the first failed read or write.
    int copyContents(const int source, const int target)
    {
        std::vector<char> buffer(COPY_BUFFER_SIZE);
        for (;;)
        {
            const auto got {::read(source, buffer.data(), buffer.size())};
            if (got == 0)
            {
                return 0;
            }
            if (got < 0)
            {
                if (errno == EINTR)
                {
                    continue;
                }
                return errno;
            }

            for (ssize_t done {0}; done < got;)
            {
                const auto put {::write(target, buffer.data() + done, static_cast<std::size_t>(got - done))};
                if (put < 0)
                {
                    if (errno == EINTR)
                    {
                        continue;
                    }
                    return errno;
                }
                done += put;
            }
        }
    }

    /**
     * @brief Copies @p source to `<tasksFd>/<fileName>` through `.<taskId>.tmp`, so the task file
     *        never exists half written.
     * @return 0, or the errno of the step that failed.
     */
    int copyInto(const std::string& source, const int tasksFd, const std::string& taskId, const std::string& fileName)
    {
        const Fd input {::open(source.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC)};
        if (!input)
        {
            return errno;
        }

        const auto tmpName {"." + taskId + TMP_SUFFIX};
        const auto createTmp {
            [&]
            { return ::openat(tasksFd, tmpName.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0660); }};

        Fd output {createTmp()};
        if (!output && errno == EEXIST)
        {
            // Left behind by an attempt that died mid-copy.
            ::unlinkat(tasksFd, tmpName.c_str(), 0);
            output = Fd {createTmp()};
        }
        if (!output)
        {
            return errno;
        }

        auto error {copyContents(input.get(), output.get())};
        // Durable before it becomes visible under its final name.
        if (error == 0 && ::fsync(output.get()) != 0)
        {
            error = errno;
        }
        const auto closeError {output.reset()};
        if (error == 0)
        {
            error = closeError;
        }
        if (error == 0 && ::renameat(tasksFd, tmpName.c_str(), tasksFd, fileName.c_str()) != 0)
        {
            error = errno;
        }
        if (error != 0)
        {
            ::unlinkat(tasksFd, tmpName.c_str(), 0);
        }
        return error;
    }
} // namespace

namespace task_manager::upgrade
{
    TaskLinks::TaskLinks(std::string upgradeDir, storage::ITaskStore& store, LinkAt linkAt)
        : m_upgradeDir {std::move(upgradeDir)}
        , m_store {store}
        , m_linkAt {linkAt ? std::move(linkAt) : LinkAt {::linkat}}
    {
        if (!m_upgradeDir.empty() && m_upgradeDir.back() != '/')
        {
            m_upgradeDir += '/';
        }
    }

    LinkStats TaskLinks::linkAndCommit(const std::vector<TaskLink>& rows, const std::function<void()>& commit)
    {
        std::lock_guard lock {m_mutex};
        LinkStats stats;

        const auto tasksDir {m_upgradeDir + TASKS_DIR};
        Fd tasksFd;
        if (::mkdir(tasksDir.c_str(), 0770) == 0 || errno == EEXIST)
        {
            tasksFd = Fd {::open(tasksDir.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)};
        }

        if (!tasksFd)
        {
            stats.lastErrno = errno;
            stats.failed = rows.size();
        }
        else
        {
            // Per source WPK, not per call: one batch can mix deb, rpm and msi packages.
            std::unordered_map<std::string, std::string> copies;

            for (const auto& row : rows)
            {
                const auto fileName {row.taskId + TASK_FILE_SUFFIX};
                // Same shape the sweep accepts, which also keeps the name inside tasks/.
                if (!isTaskFileName(fileName))
                {
                    ++stats.failed;
                    stats.lastErrno = EINVAL;
                    LOGFN_DEBUG1(upgradeLogFn(), "Task '%s': not a task id, no per-task file.", row.taskId.c_str());
                    continue;
                }
                const auto copy {copies.find(row.wpkFile)};
                const auto source {m_upgradeDir + row.wpkFile};

                const auto linked {
                    copy != copies.end()
                        ? m_linkAt(tasksFd.get(), copy->second.c_str(), tasksFd.get(), fileName.c_str(), 0)
                        : m_linkAt(AT_FDCWD, source.c_str(), tasksFd.get(), fileName.c_str(), 0)};
                if (linked == 0 || errno == EEXIST)
                {
                    ++stats.linked;
                    continue;
                }

                auto error {errno};
                // A copy that hits the link limit itself is replaced by a fresh one.
                if (linkRefused(error))
                {
                    error = copyInto(source, tasksFd.get(), row.taskId, fileName);
                    if (error == 0)
                    {
                        ++stats.copied;
                        copies[row.wpkFile] = fileName;
                        LOGFN_DEBUG1(upgradeLogFn(),
                                     "Task %s: copied '%s' because it could not be hard-linked.",
                                     row.taskId.c_str(),
                                     row.wpkFile.c_str());
                        continue;
                    }
                }

                ++stats.failed;
                stats.lastErrno = error;
                LOGFN_DEBUG1(upgradeLogFn(),
                             "Task %s: no per-task file for '%s': %s",
                             row.taskId.c_str(),
                             row.wpkFile.c_str(),
                             std::strerror(error));
            }
        }

        if (stats.failed > 0)
        {
            LOGFN_WARN(upgradeLogFn(),
                       "%zu of %zu upgrade tasks have no per-task WPK file (%zu copies made); their agents "
                       "will be sent the WPK file name instead. Last error: %s",
                       stats.failed,
                       rows.size(),
                       stats.copied,
                       std::strerror(stats.lastErrno));
        }

        commit();
        return stats;
    }

    std::size_t TaskLinks::sweep()
    {
        std::lock_guard lock {m_mutex};

        const auto tasksDir {m_upgradeDir + TASKS_DIR};
        Fd tasksFd {::open(tasksDir.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)};
        if (!tasksFd)
        {
            if (errno == ENOENT)
            {
                return 0;
            }
            throw std::runtime_error("Cannot open '" + tasksDir + "': " + std::strerror(errno));
        }

        const auto dirFd {tasksFd.get()};
        const std::unique_ptr<DIR, int (*)(DIR*)> dir {::fdopendir(dirFd), ::closedir};
        if (!dir)
        {
            throw std::runtime_error("Cannot read '" + tasksDir + "': " + std::strerror(errno));
        }
        // closedir() now owns the descriptor.
        tasksFd.release();

        // The directory is read before the ids: a file listed here was linked before its row was
        // committed, so a row it still lacks once the ids are read is a row that will never exist.
        std::vector<std::string> candidates;
        while (const auto* entry {::readdir(dir.get())})
        {
            std::string name {entry->d_name};
            if (isTaskFileName(name) || isTemporaryName(name))
            {
                candidates.push_back(std::move(name));
            }
        }

        const auto ids {m_store.agentTaskIds(TASK_TYPE)};
        const std::string suffix {TASK_FILE_SUFFIX};

        std::size_t removed {0};
        for (const auto& name : candidates)
        {
            if (!isTemporaryName(name) && ids.count(name.substr(0, name.size() - suffix.size())) != 0)
            {
                continue;
            }

            if (::unlinkat(dirFd, name.c_str(), 0) == 0)
            {
                ++removed;
            }
            else if (errno != ENOENT)
            {
                LOGFN_DEBUG1(
                    upgradeLogFn(), "Cannot remove '%s/%s': %s", tasksDir.c_str(), name.c_str(), std::strerror(errno));
            }
        }
        return removed;
    }
} // namespace task_manager::upgrade
