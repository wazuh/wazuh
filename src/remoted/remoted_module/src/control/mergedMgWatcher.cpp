/*
 * Wazuh remoted module - Merged.mg file watcher
 * Copyright (C) 2015, Wazuh Inc.
 * July 31, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "mergedMgWatcher.hpp"
#include "controlConfig.hpp"
#include <atomic>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <functional>
#include <mutex>
#include <string>
#include <sys/inotify.h>
#include <sys/select.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>

namespace remoted::control
{
    namespace
    {
        constexpr uint32_t kRootMask = IN_CREATE | IN_MOVED_TO | IN_DELETE | IN_MOVED_FROM;
        // IN_CLOSE_WRITE fires exactly once when a writer finishes a merged.mg
        // rewrite; IN_MOVED_TO covers atomic write-then-rename. IN_MODIFY is
        // deliberately omitted: it fires per write() call, causing redundant
        // hashing when the writer streams the file in chunks.
        constexpr uint32_t kGroupDirMask = IN_CLOSE_WRITE | IN_MOVED_TO;
    } // namespace

    class MergedMgWatcher::Impl
    {
    public:
        Impl(const std::string& sharedGroupsRoot,
             const std::string& multiGroupsRoot,
             std::function<void(const std::string&)> onMergedChanged)
            : m_sharedGroupsRoot(sharedGroupsRoot)
            , m_multiGroupsRoot(multiGroupsRoot)
            , m_onMergedChanged(std::move(onMergedChanged))
            , m_stopping(false)
            , m_inotifyFd(-1)
        {
            m_inotifyFd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
            if (m_inotifyFd < 0)
            {
                return;
            }

            // Watch roots so newly created group / multigroup subdirs are picked up.
            addRootWatch(m_sharedGroupsRoot);
            addRootWatch(m_multiGroupsRoot);

            // Watch existing subdirs.
            addExistingSubdirWatches(m_sharedGroupsRoot);
            addExistingSubdirWatches(m_multiGroupsRoot);

            m_watchThread = std::thread([this]() { watchLoop(); });
        }

        ~Impl()
        {
            stop();
        }

        void stop()
        {
            bool expected = false;
            if (!m_stopping.compare_exchange_strong(expected, true))
            {
                return;
            }

            if (m_watchThread.joinable())
            {
                m_watchThread.join();
            }

            if (m_inotifyFd >= 0)
            {
                std::lock_guard<std::mutex> lock(m_watchMutex);
                for (const auto& [wd, _] : m_dirWatches)
                {
                    inotify_rm_watch(m_inotifyFd, wd);
                }
                for (const auto& [wd, _] : m_rootWatches)
                {
                    inotify_rm_watch(m_inotifyFd, wd);
                }
                m_dirWatches.clear();
                m_rootWatches.clear();
                close(m_inotifyFd);
                m_inotifyFd = -1;
            }
        }

    private:
        void watchLoop()
        {
            alignas(struct inotify_event) char buffer[kInotifyBufferSize];

            while (!m_stopping.load(std::memory_order_relaxed))
            {
                fd_set fds;
                FD_ZERO(&fds);
                FD_SET(m_inotifyFd, &fds);

                struct timeval tv;
                tv.tv_sec = 1;
                tv.tv_usec = 0;

                int ret = select(m_inotifyFd + 1, &fds, nullptr, nullptr, &tv);
                if (m_stopping.load(std::memory_order_relaxed))
                {
                    break;
                }
                if (ret < 0)
                {
                    if (errno == EINTR)
                    {
                        continue;
                    }
                    break;
                }
                if (ret == 0)
                {
                    continue;
                }

                ssize_t len = read(m_inotifyFd, buffer, sizeof(buffer));
                if (len <= 0)
                {
                    if (len < 0 && errno == EINTR)
                    {
                        continue;
                    }
                    continue;
                }

                for (char* ptr = buffer; ptr < buffer + len;)
                {
                    auto* event = reinterpret_cast<struct inotify_event*>(ptr);
                    handleEvent(event);
                    ptr += sizeof(struct inotify_event) + event->len;
                }
            }
        }

        void handleEvent(struct inotify_event* event)
        {
            if (event->len == 0)
            {
                return;
            }

            std::string name(event->name);
            std::string parentDir;
            bool isRootEvent = false;

            {
                std::lock_guard<std::mutex> lock(m_watchMutex);
                if (auto it = m_rootWatches.find(event->wd); it != m_rootWatches.end())
                {
                    parentDir = it->second;
                    isRootEvent = true;
                }
                else if (auto itd = m_dirWatches.find(event->wd); itd != m_dirWatches.end())
                {
                    parentDir = itd->second;
                }
                else
                {
                    return;
                }
            }

            if (isRootEvent)
            {
                // A subdir was created / moved into the root: watch it and
                // synthesize a change so the cache is refreshed for that group.
                if (!(event->mask & IN_ISDIR))
                {
                    return;
                }

                std::string subdirPath = parentDir + "/" + name;

                if (event->mask & (IN_CREATE | IN_MOVED_TO))
                {
                    if (addSubdirWatch(subdirPath))
                    {
                        // Emit a synthetic invalidation for this subdir's merged.mg,
                        // in case the file was created together with the directory
                        // before we installed the watch.
                        m_onMergedChanged(subdirPath + "/merged.mg");
                    }
                }
                else if (event->mask & (IN_DELETE | IN_MOVED_FROM))
                {
                    removeSubdirWatch(subdirPath);
                    m_onMergedChanged(subdirPath + "/merged.mg");
                }
                return;
            }

            // Subdir event: only merged.mg matters.
            if (name != "merged.mg")
            {
                return;
            }

            m_onMergedChanged(parentDir + "/merged.mg");
        }

        void addRootWatch(const std::string& root)
        {
            int wd = inotify_add_watch(m_inotifyFd, root.c_str(), kRootMask);
            if (wd >= 0)
            {
                std::lock_guard<std::mutex> lock(m_watchMutex);
                m_rootWatches[wd] = root;
            }
        }

        void addExistingSubdirWatches(const std::string& root)
        {
            std::error_code ec;
            for (auto it = std::filesystem::directory_iterator(root, ec);
                 !ec && it != std::filesystem::directory_iterator();
                 it.increment(ec))
            {
                std::error_code isDirEc;
                if (it->is_directory(isDirEc) && !isDirEc)
                {
                    addSubdirWatch(it->path().string());
                }
            }
        }

        bool addSubdirWatch(const std::string& dirPath)
        {
            {
                std::lock_guard<std::mutex> lock(m_watchMutex);
                if (m_subdirToWd.find(dirPath) != m_subdirToWd.end())
                {
                    return false;
                }
            }

            int wd = inotify_add_watch(m_inotifyFd, dirPath.c_str(), kGroupDirMask);
            if (wd < 0)
            {
                return false;
            }

            std::lock_guard<std::mutex> lock(m_watchMutex);
            m_dirWatches[wd] = dirPath;
            m_subdirToWd[dirPath] = wd;
            return true;
        }

        void removeSubdirWatch(const std::string& dirPath)
        {
            int wd;
            {
                std::lock_guard<std::mutex> lock(m_watchMutex);
                auto it = m_subdirToWd.find(dirPath);
                if (it == m_subdirToWd.end())
                {
                    return;
                }
                wd = it->second;
                m_subdirToWd.erase(it);
                m_dirWatches.erase(wd);
            }
            inotify_rm_watch(m_inotifyFd, wd);
        }

        std::string m_sharedGroupsRoot;
        std::string m_multiGroupsRoot;
        std::function<void(const std::string&)> m_onMergedChanged;
        std::atomic<bool> m_stopping;
        int m_inotifyFd;
        std::thread m_watchThread;
        std::mutex m_watchMutex;
        std::unordered_map<int, std::string> m_rootWatches; ///< wd -> root dir path
        std::unordered_map<int, std::string> m_dirWatches;  ///< wd -> subdir path
        std::unordered_map<std::string, int> m_subdirToWd;  ///< reverse of m_dirWatches
    };

    MergedMgWatcher::MergedMgWatcher(const std::string& sharedGroupsRoot,
                                     const std::string& multiGroupsRoot,
                                     std::function<void(const std::string&)> onMergedChanged)
        : m_impl(std::make_unique<Impl>(sharedGroupsRoot, multiGroupsRoot, std::move(onMergedChanged)))
    {
    }

    MergedMgWatcher::~MergedMgWatcher() = default;

    void MergedMgWatcher::stop()
    {
        m_impl->stop();
    }

} // namespace remoted::control
