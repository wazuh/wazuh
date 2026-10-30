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

#include "fileHash.hpp"
#include "taskManagerLog.hpp"

#include <json.hpp>

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <memory>
#include <optional>
#include <regex>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>
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
     * @brief Copies what @p input reads, from its current offset, to `<tasksFd>/<fileName>` through
     *        `.<taskId>.tmp`, so the task file never exists half written.
     * @return 0, or the errno of the step that failed.
     */
    int copyFdInto(const int input, const int tasksFd, const std::string& taskId, const std::string& fileName)
    {
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

        auto error {copyContents(input, output.get())};
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

    /// @brief copyFdInto() from the file at @p source, opened without following a symlink.
    int copyInto(const std::string& source, const int tasksFd, const std::string& taskId, const std::string& fileName)
    {
        const Fd input {::open(source.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC)};
        if (!input)
        {
            return errno;
        }
        return copyFdInto(input.get(), tasksFd, taskId, fileName);
    }

    /// @brief Best effort: a failure leaves the entry to the filesystem's own write-back.
    void syncDirectory(const std::string& path, const std::function<int(int)>& sync)
    {
        const Fd dir {::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC)};
        if (dir)
        {
            sync(dir.get());
        }
    }

    bool sameFile(const struct stat& left, const struct stat& right)
    {
        return left.st_dev == right.st_dev && left.st_ino == right.st_ino;
    }

    /// @brief A plain file name directly under the upgrade directory: no separator, no NUL, not
    ///        hidden (which also rules out `.` and `..`).
    bool isPlainFileName(const std::string& name)
    {
        return !name.empty() && name.front() != '.' && name.find('/') == std::string::npos &&
               name.find('\0') == std::string::npos;
    }
} // namespace

namespace task_manager::upgrade
{
    TaskLinks::TaskLinks(std::string upgradeDir, storage::ITaskStore& store, LinkAt linkAt, Fsync fsync)
        : m_upgradeDir {std::move(upgradeDir)}
        , m_store {store}
        , m_linkAt {linkAt ? std::move(linkAt) : LinkAt {::linkat}}
        , m_fsync {fsync ? std::move(fsync) : Fsync {::fsync}}
    {
        if (!m_upgradeDir.empty() && m_upgradeDir.back() != '/')
        {
            m_upgradeDir += '/';
        }
    }

    LinkStats TaskLinks::linkAndCommit(const std::vector<TaskLink>& rows, const Commit& commit)
    {
        std::lock_guard lock {m_mutex};
        LinkStats stats;
        stats.staged.assign(rows.size(), false);

        const auto tasksDir {m_upgradeDir + TASKS_DIR};
        Fd tasksFd;
        if (::mkdir(tasksDir.c_str(), 0770) == 0)
        {
            // A new tasks/ entry must survive a crash as much as the files written into it.
            syncDirectory(m_upgradeDir, m_fsync);
            tasksFd = Fd {::open(tasksDir.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)};
        }
        else if (errno == EEXIST)
        {
            tasksFd = Fd {::open(tasksDir.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)};
        }

        std::vector<std::size_t> staged;
        if (!tasksFd)
        {
            stats.lastErrno = errno;
            stats.failed = rows.size();
        }
        else
        {
            const auto dirFd {tasksFd.get()};
            // Per source WPK, not per call: one batch can mix deb, rpm and msi packages.
            std::unordered_map<std::string, std::string> copies;
            // Read only when a task file name is already taken.
            std::optional<std::unordered_set<std::string>> taskIds;

            for (std::size_t index = 0; index < rows.size(); ++index)
            {
                const auto& row {rows[index]};
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
                const auto linkTo {
                    [&](const std::string& target)
                    {
                        const auto linked {copy != copies.end()
                                               ? m_linkAt(dirFd, copy->second.c_str(), dirFd, target.c_str(), 0)
                                               : m_linkAt(AT_FDCWD, source.c_str(), dirFd, target.c_str(), 0)};
                        return linked == 0 ? 0 : errno;
                    }};

                if (copy == copies.end())
                {
                    // linkat() without flags links a symlink itself, and /download refuses one.
                    // A swap to a symlink after this check only makes that download fail (O_NOFOLLOW).
                    struct stat origin {};

                    int notRegular {0};
                    if (::fstatat(AT_FDCWD, source.c_str(), &origin, AT_SYMLINK_NOFOLLOW) != 0)
                    {
                        notRegular = errno;
                    }
                    else if (!S_ISREG(origin.st_mode))
                    {
                        notRegular = S_ISDIR(origin.st_mode) ? EISDIR : S_ISLNK(origin.st_mode) ? ELOOP : EINVAL;
                    }

                    if (notRegular != 0)
                    {
                        ++stats.failed;
                        stats.lastErrno = notRegular;
                        LOGFN_DEBUG1(upgradeLogFn(),
                                     "Task %s: no per-task file for '%s': %s",
                                     row.taskId.c_str(),
                                     row.wpkFile.c_str(),
                                     std::strerror(notRegular));
                        continue;
                    }
                }

                auto error {linkTo(fileName)};
                if (error == EEXIST)
                {
                    struct stat existing {};
                    struct stat origin {};

                    if (::fstatat(dirFd, fileName.c_str(), &existing, AT_SYMLINK_NOFOLLOW) != 0)
                    {
                        error = errno;
                    }
                    else if (S_ISREG(existing.st_mode) &&
                             ((::fstatat(AT_FDCWD, source.c_str(), &origin, AT_SYMLINK_NOFOLLOW) == 0 &&
                               sameFile(existing, origin)) ||
                              (copy != copies.end() &&
                               ::fstatat(dirFd, copy->second.c_str(), &origin, AT_SYMLINK_NOFOLLOW) == 0 &&
                               sameFile(existing, origin))))
                    {
                        error = 0;
                    }
                    else
                    {
                        if (!taskIds)
                        {
                            try
                            {
                                taskIds = m_store.agentTaskIds(TASK_TYPE);
                            }
                            catch (const std::exception& exception)
                            {
                                LOGFN_DEBUG1(upgradeLogFn(), "Cannot read the upgrade task ids: %s", exception.what());
                            }
                        }

                        if (!taskIds)
                        {
                            // Without the ids an orphan cannot be told from the file of a stored row.
                            error = EIO;
                        }
                        else if (taskIds->count(row.taskId) != 0)
                        {
                            // The file of a stored row is never replaced: an agent may be downloading it.
                            // The store reports the id as existing.
                            error = S_ISREG(existing.st_mode) ? 0 : EEXIST;
                        }
                        else if (S_ISDIR(existing.st_mode) && ::unlinkat(dirFd, fileName.c_str(), AT_REMOVEDIR) != 0)
                        {
                            // renameat() cannot replace a directory; a non-empty one stays.
                            error = errno;
                        }
                        else
                        {
                            // An orphan: replaced in one step, through a temporary.
                            const auto tmpName {"." + row.taskId + TMP_SUFFIX};
                            ::unlinkat(dirFd, tmpName.c_str(), 0);
                            error = linkTo(tmpName);
                            if (error == 0 && ::renameat(dirFd, tmpName.c_str(), dirFd, fileName.c_str()) != 0)
                            {
                                error = errno;
                                ::unlinkat(dirFd, tmpName.c_str(), 0);
                            }
                        }
                    }
                }

                if (error == 0)
                {
                    ++stats.linked;
                    stats.staged[index] = true;
                    continue;
                }

                // A copy that hits the link limit itself is replaced by a fresh one. The copy also
                // replaces an orphan, through its own temporary.
                if (linkRefused(error))
                {
                    error = copyInto(source, dirFd, row.taskId, fileName);
                    if (error == 0)
                    {
                        ++stats.copied;
                        stats.staged[index] = true;
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

            for (std::size_t index = 0; index < rows.size(); ++index)
            {
                if (stats.staged[index])
                {
                    staged.push_back(index);
                }
            }

            // A file whose directory entry is not durable could vanish after the row is committed.
            // Files of rows left uncommitted are removed by the next sweep.
            if (!staged.empty() && m_fsync(dirFd) != 0)
            {
                stats.lastErrno = errno;
                stats.failed = rows.size();
                stats.staged.assign(rows.size(), false);
                staged.clear();
            }
        }

        if (stats.failed > 0)
        {
            LOGFN_WARN(upgradeLogFn(),
                       "%zu of %zu upgrade tasks were not created because their per-task WPK file could not be "
                       "prepared (%zu copies made). Last error: %s",
                       stats.failed,
                       rows.size(),
                       stats.copied,
                       std::strerror(stats.lastErrno));
        }

        commit(staged);
        return stats;
    }

    BackfillStats TaskLinks::backfill()
    {
        std::lock_guard lock {m_mutex};
        BackfillStats stats;

        const auto rows {m_store.pendingAgentTasksByType(TASK_TYPE)};
        if (rows.empty())
        {
            return stats;
        }

        const auto tasksDir {m_upgradeDir + TASKS_DIR};
        Fd tasksFd;
        if (::mkdir(tasksDir.c_str(), 0770) == 0)
        {
            // A new tasks/ entry must survive a crash as much as the files written into it.
            syncDirectory(m_upgradeDir, m_fsync);
            tasksFd = Fd {::open(tasksDir.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)};
        }
        else if (errno == EEXIST)
        {
            tasksFd = Fd {::open(tasksDir.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)};
        }
        if (!tasksFd)
        {
            throw std::runtime_error("Cannot open '" + tasksDir + "': " + std::strerror(errno));
        }
        const auto dirFd {tasksFd.get()};

        // One per WPK name: opened and hashed once however many rows share it.
        struct Source
        {
            bool opened {false};
            Fd fd;
            struct stat info {};
            std::optional<std::string> sha1;
            // Set when the WPK could not be read for a reason that may not last (EMFILE, EIO...):
            // its rows stay pending rather than expire, which cannot be undone.
            bool transient {false};
        };
        std::unordered_map<std::string, Source> sources;
        std::vector<std::string> rejected;
        std::size_t deferred {0};

        const auto reject {[&](const AgentTask& row, const char* reason)
                           {
                               rejected.push_back(row.taskId);
                               LOGFN_DEBUG1(upgradeLogFn(), "Task %s: %s.", row.taskId.c_str(), reason);
                           }};

        for (const auto& row : rows)
        {
            const auto fileName {row.taskId + TASK_FILE_SUFFIX};
            if (!isTaskFileName(fileName))
            {
                reject(row, "not a task id");
                continue;
            }

            struct stat existing {};

            if (::fstatat(dirFd, fileName.c_str(), &existing, AT_SYMLINK_NOFOLLOW) == 0)
            {
                if (!S_ISREG(existing.st_mode))
                {
                    reject(row, "its task file is not a regular file");
                }
                continue;
            }
            if (errno != ENOENT)
            {
                LOGFN_DEBUG1(upgradeLogFn(),
                             "Cannot check '%s/%s': %s",
                             tasksDir.c_str(),
                             fileName.c_str(),
                             std::strerror(errno));
                continue;
            }

            const auto payload = nlohmann::json::parse(row.payload, nullptr, false);
            if (!payload.is_object())
            {
                reject(row, "unreadable payload");
                continue;
            }
            const auto wpkFile {payload.find("wpk_file")};
            const auto wpkSha1 {payload.find("wpk_sha1")};
            if (wpkFile == payload.end() || !wpkFile->is_string() || wpkSha1 == payload.end() || !wpkSha1->is_string())
            {
                reject(row, "no wpk_file or wpk_sha1 in its payload");
                continue;
            }
            const auto& name {wpkFile->get_ref<const std::string&>()};
            if (!isPlainFileName(name))
            {
                reject(row, "its WPK is not a file directly under the upgrade directory");
                continue;
            }

            auto& source {sources[name]};
            if (!source.opened)
            {
                source.opened = true;
                // O_NONBLOCK: a FIFO under that name must not block the module's start.
                source.fd = Fd {::open((m_upgradeDir + name).c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)};
                if (!source.fd)
                {
                    source.transient = errno != ENOENT && errno != ELOOP && errno != ENOTDIR;
                }
                else if (::fstat(source.fd.get(), &source.info) != 0)
                {
                    source.transient = true;
                }
                else if (S_ISREG(source.info.st_mode))
                {
                    source.sha1 = sha1OfFd(source.fd.get());
                    source.transient = !source.sha1.has_value();
                }
            }
            if (source.transient)
            {
                ++deferred;
                LOGFN_DEBUG1(upgradeLogFn(), "Task %s: its WPK cannot be read now, left pending.", row.taskId.c_str());
                continue;
            }
            if (!source.sha1 || !sha1Equals(*source.sha1, wpkSha1->get_ref<const std::string&>()))
            {
                reject(row, "its WPK is missing or changed");
                continue;
            }

            bool copied {false};
            auto error {m_linkAt(AT_FDCWD, (m_upgradeDir + name).c_str(), dirFd, fileName.c_str(), 0) == 0 ? 0 : errno};
            if (linkRefused(error))
            {
                // Copied from the descriptor that was hashed, not from the name, which may have changed.
                copied = true;
                error = ::lseek(source.fd.get(), 0, SEEK_SET) == 0
                            ? copyFdInto(source.fd.get(), dirFd, row.taskId, fileName)
                            : errno;
            }
            if (error != 0)
            {
                reject(row, "its task file could not be created");
                continue;
            }

            // The name was linked, not the descriptor: a link must be the very file hashed, and a copy
            // at least as long.
            struct stat result {};

            if (::fstatat(dirFd, fileName.c_str(), &result, AT_SYMLINK_NOFOLLOW) != 0 || !S_ISREG(result.st_mode) ||
                result.st_size != source.info.st_size || (!copied && !sameFile(result, source.info)))
            {
                ::unlinkat(dirFd, fileName.c_str(), 0);
                reject(row, "its WPK changed while its task file was created");
                continue;
            }
            ++stats.staged;
        }

        // The rows stay pending either way: a file lost to a crash is given again on the next start.
        if (stats.staged > 0 && m_fsync(dirFd) != 0)
        {
            LOGFN_WARN(upgradeLogFn(), "Cannot sync '%s': %s", tasksDir.c_str(), std::strerror(errno));
        }

        if (!rejected.empty())
        {
            stats.expired = static_cast<std::size_t>(m_store.expireAgentTasksById(rejected));
        }

        if (stats.staged > 0 || stats.expired > 0 || deferred > 0)
        {
            LOGFN_WARN(upgradeLogFn(),
                       "%zu pending upgrade tasks given a WPK file, %zu expired because their WPK is missing or "
                       "changed, %zu left pending because their WPK cannot be read now",
                       stats.staged,
                       stats.expired,
                       deferred);
        }
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
