/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * April 8, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef ASYNC_FLUSH_CONTROLLER_HPP
#define ASYNC_FLUSH_CONTROLLER_HPP

#include <exception>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <utility>

#include "logging_helper.h"

namespace Utils
{
    /// @brief Runs one module flush in a background thread and tracks the result.
    ///
    /// This class does not know how a module flush works. The caller gives it a
    /// blocking flush callback, and this class runs that callback in one worker
    /// thread, tracks whether it is still running, and stores the last result.
    class AsyncFlushController final
    {
    public:
        /// @brief Simple view of the current flush state.
        struct FlushStatus final
        {
            /// @brief True while the worker thread is still flushing.
            bool running;

            /// @brief True when the last completed flush finished without error.
            ///
            /// When no flush has run yet, this stays true so callers can treat
            /// the idle state as "nothing pending".
            bool successful;
        };

        /// @brief Blocking function that performs the real flush work.
        ///
        /// Return 0 on success and -1 on failure.
        using FlushFunction = std::function<int()>;

        /// @brief Optional logger used for debug and error messages.
        using LogFunction = std::function<void(modules_log_level_t, const std::string&)>;

        /// @brief Builds a controller for one module.
        /// @param moduleName Name used in log messages.
        /// @param flushFunction Blocking function that performs the flush work.
        /// @param logFunction Optional logger.
        AsyncFlushController(std::string moduleName, FlushFunction flushFunction, LogFunction logFunction = nullptr)
            : m_moduleName {std::move(moduleName)}
            , m_flushFunction {std::move(flushFunction)}
            , m_logFunction {std::move(logFunction)}
        {
        }

        AsyncFlushController(const AsyncFlushController&) = delete;
        AsyncFlushController& operator=(const AsyncFlushController&) = delete;

        /// @brief Waits for any running flush worker before the controller is destroyed.
        ~AsyncFlushController()
        {
            waitForFlushToFinish();
        }

        /// @brief Starts a flush in the background if one is not already running.
        ///
        /// If a flush is already running, this method keeps the current worker
        /// and returns true. It does not wait for the flush to finish.
        /// @return Always true. The caller-provided flush function reports the real result.
        bool startFlush()
        {
            std::thread previousWorker;

            {
                std::lock_guard<std::mutex> lock {m_mutex};

                if (m_workerState == WorkerState::RUNNING)
                {
                    logMessage(LOG_DEBUG, m_moduleName + " async flush already in progress");
                    return true;
                }

                if (m_worker.joinable())
                {
                    previousWorker = std::move(m_worker);
                }

                m_workerState = WorkerState::RUNNING;
                m_worker = std::thread(&AsyncFlushController::runFlushInBackground, this);
            }

            if (previousWorker.joinable())
            {
                previousWorker.join();
            }

            logMessage(LOG_DEBUG, m_moduleName + " async flush requested");
            return true;
        }

        /// @brief Returns the current flush state.
        ///
        /// The idle state is reported as "not running" and "successful" so the
        /// caller can treat it like "there is nothing left to wait for".
        FlushStatus getFlushStatus() const
        {
            std::lock_guard<std::mutex> lock {m_mutex};

            switch (m_workerState)
            {
                case WorkerState::RUNNING: return {true, false};
                case WorkerState::FAILED: return {false, false};
                case WorkerState::IDLE:
                case WorkerState::SUCCEEDED:
                default: return {false, true};
            }
        }

        /// @brief Waits until the current flush worker finishes.
        ///
        /// This method only joins the worker thread. It does not cancel the
        /// flush. Callers should stop their module or sync protocol first when
        /// they need the flush to exit early.
        void waitForFlushToFinish()
        {
            std::thread worker;

            {
                std::lock_guard<std::mutex> lock {m_mutex};
                if (m_worker.joinable())
                {
                    worker = std::move(m_worker);
                }
            }

            if (worker.joinable())
            {
                worker.join();
            }
        }

    private:
        /// @brief Internal state of the background flush worker.
        enum class WorkerState
        {
            IDLE,
            RUNNING,
            SUCCEEDED,
            FAILED
        };

        /// @brief Runs the blocking flush function and stores the final result.
        void runFlushInBackground()
        {
            int result = -1;

            try
            {
                result = m_flushFunction ? m_flushFunction() : -1;
            }
            catch (const std::exception& ex)
            {
                logMessage(LOG_ERROR, m_moduleName + " async flush failed with exception: " + std::string(ex.what()));
                result = -1;
            }
            catch (...)
            {
                logMessage(LOG_ERROR, m_moduleName + " async flush failed with unknown exception");
                result = -1;
            }

            {
                std::lock_guard<std::mutex> lock {m_mutex};
                m_workerState = (result == 0) ? WorkerState::SUCCEEDED : WorkerState::FAILED;
            }
        }

        /// @brief Sends a message to the optional logger.
        void logMessage(modules_log_level_t level, const std::string& message) const
        {
            if (m_logFunction)
            {
                m_logFunction(level, message);
            }
        }

        const std::string m_moduleName;
        FlushFunction m_flushFunction;
        LogFunction m_logFunction;
        mutable std::mutex m_mutex;
        std::thread m_worker;
        WorkerState m_workerState {WorkerState::IDLE};
    };
} // namespace Utils

#endif // ASYNC_FLUSH_CONTROLLER_HPP
