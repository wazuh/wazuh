/*
 * Wazuh task manager module
 * Copyright (C) 2015, Wazuh Inc.
 * September 3, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _TASK_MANAGER_TEST_UPGRADE_DOUBLES_HPP
#define _TASK_MANAGER_TEST_UPGRADE_DOUBLES_HPP

#include "upgrade/iWpkRepository.hpp"

#include <uds_http_server/IUdsHttpServer.hpp>

#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace task_manager::test
{
    /**
     * @brief A scriptable WPK repository that records what was asked of it.
     *
     * Not a gmock. What these tests assert is how many times the repository was TOUCHED from several
     * threads at once -- the whole point of the caches is that the answer is one, not five hundred --
     * and a call-count expectation set up front cannot express "however many agents there are, this
     * must happen once". Same reasoning as TestHandler in testDoubles.hpp.
     *
     * Thread-safe: the caches call it from several workers concurrently, which is the case under test.
     */
    class FakeWpkRepository final : public upgrade::IWpkRepository
    {
    public:
        struct VersionsScript
        {
            bool ok {true};
            std::string body;
            int httpStatus {200};
            /// @brief Fail this many times before starting to succeed.
            int failuresRemaining {0};
        };

        struct DownloadScript
        {
            bool ok {true};
            /// @brief Bytes written to destPath. Their real sha1 is what the cache will verify.
            std::string content;
            int httpStatus {200};
            int failuresRemaining {0};
            /// @brief Sleep before answering, so a concurrency test has a window to observe.
            std::chrono::milliseconds delay {0};
            /// @brief Write the content but report failure, to exercise partial-file cleanup.
            bool writeThenFail {false};
        };

        void scriptVersions(const std::string& url, VersionsScript script)
        {
            std::lock_guard lock {m_mutex};
            m_versions[url] = std::move(script);
        }

        void scriptDownload(const std::string& url, DownloadScript script)
        {
            std::lock_guard lock {m_mutex};
            m_downloads[url] = std::move(script);
        }

        upgrade::RepoResult fetchVersions(const std::string& url, std::string& body) override
        {
            VersionsScript script;
            {
                std::lock_guard lock {m_mutex};
                ++m_versionsCalls[url];
                ++m_totalVersionsCalls;

                const auto found {m_versions.find(url)};
                if (found == m_versions.end())
                {
                    return {false, 0, 404, false};
                }

                if (found->second.failuresRemaining > 0)
                {
                    --found->second.failuresRemaining;
                    return {false, 7, 0, false};
                }

                script = found->second;
            }

            if (!script.ok)
            {
                return {false, 0, script.httpStatus, false};
            }

            body = script.body;
            return {true, 0, script.httpStatus, false};
        }

        upgrade::RepoResult
        download(const std::string& url, const std::string& destPath, const StopToken& stop) override
        {
            DownloadScript script;
            {
                std::lock_guard lock {m_mutex};
                ++m_downloadCalls[url];
                ++m_totalDownloadCalls;
                m_peakConcurrent = std::max(m_peakConcurrent, ++m_inFlight);

                const auto found {m_downloads.find(url)};
                if (found == m_downloads.end())
                {
                    --m_inFlight;
                    return {false, 0, 404, false};
                }

                if (found->second.failuresRemaining > 0)
                {
                    --found->second.failuresRemaining;
                    --m_inFlight;
                    return {false, 7, 0, false};
                }

                script = found->second;
            }

            if (script.delay.count() > 0)
            {
                std::this_thread::sleep_for(script.delay);
            }

            upgrade::RepoResult result;

            if (stop.stopRequested())
            {
                result.aborted = true;
            }
            else if (script.ok || script.writeThenFail)
            {
                if (std::FILE* file {std::fopen(destPath.c_str(), "wb")}; file != nullptr)
                {
                    std::fwrite(script.content.data(), 1, script.content.size(), file);
                    std::fclose(file);
                    result.ok = script.ok && !script.writeThenFail;
                }
                result.httpStatus = script.httpStatus;
            }
            else
            {
                result.httpStatus = script.httpStatus;
            }

            {
                std::lock_guard lock {m_mutex};
                --m_inFlight;
            }

            return result;
        }

        void requestStop() override
        {
            std::lock_guard lock {m_mutex};
            m_stopped = true;
        }

        bool stopped()
        {
            std::lock_guard lock {m_mutex};
            return m_stopped;
        }

        std::size_t versionsCalls(const std::string& url)
        {
            std::lock_guard lock {m_mutex};
            return m_versionsCalls[url];
        }

        std::size_t downloadCalls(const std::string& url)
        {
            std::lock_guard lock {m_mutex};
            return m_downloadCalls[url];
        }

        std::size_t totalVersionsCalls()
        {
            std::lock_guard lock {m_mutex};
            return m_totalVersionsCalls;
        }

        std::size_t totalDownloadCalls()
        {
            std::lock_guard lock {m_mutex};
            return m_totalDownloadCalls;
        }

        /// @brief The most downloads that were ever in flight together. Proves the global cap holds.
        int peakConcurrentDownloads()
        {
            std::lock_guard lock {m_mutex};
            return m_peakConcurrent;
        }

    private:
        std::mutex m_mutex;
        std::map<std::string, VersionsScript> m_versions;
        std::map<std::string, DownloadScript> m_downloads;
        std::map<std::string, std::size_t> m_versionsCalls;
        std::map<std::string, std::size_t> m_downloadCalls;
        std::size_t m_totalVersionsCalls {0};
        std::size_t m_totalDownloadCalls {0};
        int m_inFlight {0};
        int m_peakConcurrent {0};
        bool m_stopped {false};
    };

    /**
     * @brief An IHttpResponder that records what it was sent, and whether it was sent anything.
     *
     * The "whether" is the point. Dropping a responder without answering makes the transport reply
     * 503 -- which the Server API raises on rather than retrying -- so "every parked request is
     * answered" is a real guarantee that needs a real assertion, and only a double can see it.
     */
    class FakeResponder final : public wazuh::uds_http::IHttpResponder
    {
    public:
        void send(wazuh::uds_http::HttpResponse response) override
        {
            std::lock_guard lock {m_mutex};
            // The transport's own contract: send() takes effect exactly once, extra calls ignored.
            // Reproduced here so a double-send shows up as a test failure rather than being masked.
            if (m_sent)
            {
                ++m_extraSends;
                return;
            }
            m_sent = true;
            m_status = response.status;
            m_body = std::move(response.body);
            m_answered.notify_all();
        }

        bool answered() const
        {
            std::lock_guard lock {m_mutex};
            return m_sent;
        }

        int status() const
        {
            std::lock_guard lock {m_mutex};
            return m_status;
        }

        std::string body() const
        {
            std::lock_guard lock {m_mutex};
            return m_body;
        }

        int extraSends() const
        {
            std::lock_guard lock {m_mutex};
            return m_extraSends;
        }

        bool waitForAnswer(const std::chrono::milliseconds timeout)
        {
            std::unique_lock lock {m_mutex};
            return m_answered.wait_for(lock, timeout, [this] { return m_sent; });
        }

    private:
        mutable std::mutex m_mutex;
        std::condition_variable m_answered;
        bool m_sent {false};
        int m_status {0};
        int m_extraSends {0};
        std::string m_body;
    };

    /**
     * @brief A directory that exists for the life of the test and takes its contents with it.
     */
    class TempDir
    {
    public:
        TempDir()
        {
            std::string pattern {"/tmp/wazuh_upgrade_test_XXXXXX"};
            m_path = ::mkdtemp(pattern.data()) != nullptr ? pattern + "/" : std::string {};
        }

        ~TempDir()
        {
            if (!m_path.empty())
            {
                // Depth-2 is enough: the cache creates exactly one subdirectory, .staging/.
                const auto command {"rm -rf '" + m_path + "'"};
                if (std::system(command.c_str()) != 0)
                {
                    // Nothing useful to do in a destructor; the tmpdir is reaped by the OS anyway.
                }
            }
        }

        TempDir(const TempDir&) = delete;
        TempDir& operator=(const TempDir&) = delete;

        const std::string& path() const { return m_path; }

        void writeFile(const std::string& name, const std::string& content) const
        {
            std::FILE* file {std::fopen((m_path + name).c_str(), "wb")};
            if (file != nullptr)
            {
                std::fwrite(content.data(), 1, content.size(), file);
                std::fclose(file);
            }
        }

        bool exists(const std::string& name) const
        {
            std::FILE* file {std::fopen((m_path + name).c_str(), "rb")};
            if (file == nullptr)
            {
                return false;
            }
            std::fclose(file);
            return true;
        }

        std::string read(const std::string& name) const
        {
            std::string content;
            if (std::FILE* file {std::fopen((m_path + name).c_str(), "rb")}; file != nullptr)
            {
                char block[4096];
                std::size_t read {0};
                while ((read = std::fread(block, 1, sizeof(block), file)) > 0)
                {
                    content.append(block, read);
                }
                std::fclose(file);
            }
            return content;
        }

    private:
        std::string m_path;
    };
} // namespace task_manager::test

#endif // _TASK_MANAGER_TEST_UPGRADE_DOUBLES_HPP
