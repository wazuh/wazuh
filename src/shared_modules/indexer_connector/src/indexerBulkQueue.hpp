/*
 * Wazuh - Indexer Connector Bulk Queue.
 * Copyright (C) 2015, Wazuh Inc.
 * June 29, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INDEXER_BULK_QUEUE_HPP
#define _INDEXER_BULK_QUEUE_HPP

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "commonDefs.h"
#include "loggerHelper.h"

/**
 * @brief High-performance bulk queue for the Indexer Connector.
 *
 * Accepts string payloads via move semantics, accumulates them in an internal
 * deque, and dispatches batches to a processor callback on a background thread.
 * Capacity is limited by total byte count (predictable memory usage).
 */
class IndexerBulkQueue final
{
public:
    using Processor = std::function<void(std::vector<std::string>&)>;

    /**
     * @param processor  Callback invoked on the worker thread with each batch.
     * @param maxBytes   Maximum bytes before push() starts discarding (0 = unlimited).
     * @param bulkMaxBytes  Target byte threshold per batch before dispatch.
     * @param flushIntervalSec  Max seconds to wait before flushing a partial batch.
     * @param retryDelaySec     Seconds to sleep after a failed processor call.
     */
    IndexerBulkQueue(Processor processor,
                     size_t maxBytes,
                     size_t bulkMaxBytes,
                     size_t flushIntervalSec,
                     size_t retryDelaySec)
        : m_processor(std::move(processor))
        , m_maxBytes(maxBytes)
        , m_bulkMaxBytes(bulkMaxBytes)
        , m_flushInterval(flushIntervalSec)
        , m_retryDelay(retryDelaySec)
    {
        m_worker = std::thread(&IndexerBulkQueue::dispatch, this);
    }

    ~IndexerBulkQueue()
    {
        stop();
    }

    IndexerBulkQueue(const IndexerBulkQueue&) = delete;
    IndexerBulkQueue& operator=(const IndexerBulkQueue&) = delete;

    /// Push a payload into the queue (move). Discards if byte limit is exceeded.
    void push(std::string&& data)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_running)
            return;

        const auto dataSize = data.size();

        if (m_maxBytes != 0 && m_totalBytes + dataSize > m_maxBytes)
        {
            ++m_droppedCount;
            ++m_totalDroppedCount;
            logOverflow(dataSize);
            return;
        }

        m_totalBytes += dataSize;
        m_buffer.push_back(std::move(data));

        // Log recovery after overflow
        if (m_droppedCount > 0)
        {
            logInfo(LOGGER_DEFAULT_TAG,
                    "Queue size normalized. Resuming event acceptance after %zu discarded events.",
                    m_droppedCount.load());
            m_droppedCount = 0;
            m_firstOverflowLogged = false;
        }

        // Wake worker if accumulated bytes reach the bulk threshold
        if (m_totalBytes >= m_bulkMaxBytes.load())
        {
            m_cv.notify_one();
        }
    }

    /// Convenience overload for string_view (copies into a string, then moves).
    void push(std::string_view data)
    {
        push(std::string(data));
    }

    /// Signal the worker to stop and wait for it to finish.
    void stop()
    {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (!m_running)
                return;
            m_running = false;
        }
        m_cv.notify_one();
        if (m_worker.joinable())
        {
            m_worker.join();
        }
    }

    /// Total bytes currently in the queue.
    uint64_t byteSize() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_totalBytes;
    }

    /// Total events dropped since construction.
    uint64_t droppedEvents() const
    {
        return m_totalDroppedCount.load();
    }

    /// Current bulk max bytes threshold.
    size_t bulkMaxBytes() const
    {
        return m_bulkMaxBytes.load();
    }

    /// Dynamically adjust bulk max bytes (e.g. after 413 errors).
    void bulkMaxBytes(size_t newSize)
    {
        m_bulkMaxBytes.store(newSize);
    }

private:
    void dispatch()
    {
        while (true)
        {
            std::vector<std::string> batch;

            {
                std::unique_lock<std::mutex> lock(m_mutex);
                m_cv.wait_for(lock, std::chrono::seconds(m_flushInterval), [this]()
                              { return !m_running || m_totalBytes >= m_bulkMaxBytes.load(); });

                if (!m_running && m_buffer.empty())
                    break;

                if (m_buffer.empty())
                    continue;

                // Drain items until batch bytes >= bulkMaxBytes or buffer empty.
                // Always take at least 1 item (handles oversized single items).
                const size_t threshold = m_bulkMaxBytes.load();
                size_t batchBytes = 0;

                while (!m_buffer.empty() && (batchBytes < threshold || batch.empty()))
                {
                    const auto itemSize = m_buffer.front().size();
                    m_totalBytes -= itemSize;
                    batchBytes += itemSize;
                    batch.push_back(std::move(m_buffer.front()));
                    m_buffer.pop_front();
                }
            }

            try
            {
                m_processor(batch);
            }
            catch (const std::exception& ex)
            {
                if (m_running)
                {
                    logWarn(LOGGER_DEFAULT_TAG, "IndexerBulkQueue dispatch error: %s", ex.what());
                    std::this_thread::sleep_for(std::chrono::seconds(m_retryDelay));
                }
            }
        }
    }

    void logOverflow(size_t attemptedBytes)
    {
        const auto now = std::chrono::steady_clock::now();

        if (!m_firstOverflowLogged)
        {
            m_firstOverflowLogged = true;
            logWarn(LOGGER_DEFAULT_TAG,
                    "Queue is full (bytes: %llu, max: %zu). Starting to discard events. "
                    "Periodic summaries will be logged every %zu seconds.",
                    static_cast<unsigned long long>(m_totalBytes),
                    m_maxBytes,
                    m_summaryInterval);
            m_lastSummaryTime = now;
            m_lastSummaryDropped = m_totalDroppedCount.load();
        }
        else
        {
            const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - m_lastSummaryTime).count();
            if (elapsed >= static_cast<long long>(m_summaryInterval))
            {
                const auto currentTotal = m_totalDroppedCount.load();
                logWarn(LOGGER_DEFAULT_TAG,
                        "Queue overflow continues: %zu events discarded in the last %lld seconds "
                        "(bytes: %llu, max: %zu, total discarded: %zu).",
                        currentTotal - m_lastSummaryDropped,
                        elapsed,
                        static_cast<unsigned long long>(m_totalBytes),
                        m_maxBytes,
                        currentTotal);
                m_lastSummaryTime = now;
                m_lastSummaryDropped = currentTotal;
            }
        }
    }

    // Data
    std::deque<std::string> m_buffer;
    uint64_t m_totalBytes {0};
    const size_t m_maxBytes;
    std::atomic<size_t> m_bulkMaxBytes;
    const size_t m_flushInterval;
    const size_t m_retryDelay;

    // Threading
    mutable std::mutex m_mutex;
    std::condition_variable m_cv;
    std::thread m_worker;
    bool m_running {true};

    // Processor
    Processor m_processor;

    // Overflow tracking
    std::atomic<size_t> m_droppedCount {0};
    std::atomic<size_t> m_totalDroppedCount {0};
    bool m_firstOverflowLogged {false};
    std::chrono::steady_clock::time_point m_lastSummaryTime;
    size_t m_lastSummaryDropped {0};
    static constexpr size_t m_summaryInterval {30};
};

#endif // _INDEXER_BULK_QUEUE_HPP
