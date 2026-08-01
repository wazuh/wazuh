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
#include "exponentialBackoff.hpp"
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
    using Processor = std::function<void(uint64_t sequence, std::vector<std::string>&)>;

    /**
     * @param processor  Callback invoked on the worker thread with each batch.
     * @param maxBytes   Maximum bytes before push() starts discarding (0 = unlimited).
     * @param bulkMaxBytes  Target byte threshold per batch before dispatch.
     * @param flushIntervalSec  Max seconds to wait before flushing a partial batch.
     * @param retryDelaySec     Base delay in seconds for exponential backoff after failed processor calls.
     * @param maxRetryDelaySec  Maximum delay in seconds for exponential backoff.
     */
    IndexerBulkQueue(Processor processor,
                     size_t maxBytes,
                     size_t bulkMaxBytes,
                     size_t flushIntervalSec,
                     size_t retryDelaySec,
                     size_t maxRetryDelaySec)
        : m_processor(std::move(processor))
        , m_maxBytes(maxBytes)
        , m_bulkMaxBytes(bulkMaxBytes)
        , m_flushInterval(flushIntervalSec)
        , m_backoff(std::chrono::seconds(retryDelaySec), std::chrono::seconds(maxRetryDelaySec))
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

    /// Requests a pause (shared backoff) before the dispatch thread's next send - e.g. an OpenSearch
    /// HTTP 200 with a per-item cluster_block_exception. Coalesces repeated calls into one pause.
    ///
    /// @param sequence Batch's sequence id (see Processor). Only applied if newer than the last
    ///                 applied report, so a stale, out-of-order classification can't win.
    void requestBackoff(uint64_t sequence)
    {
        std::lock_guard<std::mutex> lock(m_backoffStateMutex);
        if (sequence > m_lastReportedSequence)
        {
            m_lastReportedSequence = sequence;
            m_externalBackoffPending = true;
        }
    }

    /// Confirms `sequence`'s response was classified as NOT indicating a blocked indexer - the only
    /// place the backoff resets (never implicitly in dispatch(), see below). Same out-of-order
    /// protection as requestBackoff().
    void reportHealthyResponse(uint64_t sequence)
    {
        std::lock_guard<std::mutex> lock(m_backoffStateMutex);
        if (sequence > m_lastReportedSequence)
        {
            m_lastReportedSequence = sequence;
            m_externalBackoffPending = false;
            m_backoff.reset();
        }
    }

private:
    void dispatch()
    {
        // Set on failure (see catch below); the resulting pause happens up here, before the *next*
        // send, alongside external backoff requests. Local to this thread only.
        bool retryPending = false;

        while (true)
        {
            // Checked before touching the buffer, so a pause always protects the very next batch and
            // never holds a local `batch` mid-sleep (safe to discard on shutdown via the block below).
            // No implicit reset when neither is pending: that could just mean classification for the
            // batch we just sent hasn't finished yet, not that it's confirmed healthy - m_backoff only
            // resets in reportHealthyResponse().
            bool externalBackoffRequested;
            std::chrono::milliseconds delay {};
            {
                std::lock_guard<std::mutex> lock(m_backoffStateMutex);
                externalBackoffRequested = m_externalBackoffPending;
                m_externalBackoffPending = false;
                if (retryPending || externalBackoffRequested)
                {
                    delay = m_backoff.nextDelay();
                }
            }

            if (retryPending || externalBackoffRequested)
            {
                retryPending = false;
                logDebug1(LOGGER_DEFAULT_TAG,
                          "IndexerBulkQueue: pausing %lld ms before next send (%s).",
                          static_cast<long long>(delay.count()),
                          externalBackoffRequested ? "external backoff requested" : "previous send failed");
                std::unique_lock<std::mutex> lock(m_mutex);
                m_cv.wait_for(lock, delay, [this]() { return !m_running; });
            }

            std::vector<std::string> batch;

            {
                std::unique_lock<std::mutex> lock(m_mutex);
                m_cv.wait_for(lock,
                              std::chrono::seconds(m_flushInterval),
                              [this]() { return !m_running || m_totalBytes >= m_bulkMaxBytes.load(); });

                if (!m_running)
                {
                    // Stopping: don't try to flush what's left over the network, that could block
                    // shutdown indefinitely (e.g. if the indexer is unreachable). Discard it instead.
                    if (!m_buffer.empty())
                    {
                        for (const auto& item : m_buffer)
                        {
                            logDebug2(LOGGER_DEFAULT_TAG, "Discarding queued event on shutdown: %s", item.c_str());
                        }
                        logDebug1(LOGGER_DEFAULT_TAG,
                                  "IndexerBulkQueue stopping: discarding %zu queued event(s) (%llu bytes) "
                                  "that were not yet sent.",
                                  m_buffer.size(),
                                  static_cast<unsigned long long>(m_totalBytes));
                        m_buffer.clear();
                        m_totalBytes = 0;
                    }
                    break;
                }

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
                // Assigned per send attempt (including retries of a failed batch), not per batch
                // content: each attempt gets a fresh HTTP response of its own to classify.
                m_processor(++m_nextSequence, batch);
            }
            catch (const std::exception& ex)
            {
                bool shouldRetry = false;
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    if (m_running)
                    {
                        shouldRetry = true;
                        // Requeue at the front (preserves order) for retry - possibly split smaller if
                        // the processor just reduced the bulk threshold (e.g. after a 413).
                        for (auto it = batch.rbegin(); it != batch.rend(); ++it)
                        {
                            m_totalBytes += it->size();
                            m_buffer.push_front(std::move(*it));
                        }
                    }
                }

                if (shouldRetry)
                {
                    logDebug1(LOGGER_DEFAULT_TAG,
                              "IndexerBulkQueue dispatch error: %s. Will retry after backoff.",
                              ex.what());
                    retryPending = true;
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
    // Assigned per send attempt in dispatch() (the only writer, no sync needed); tags
    // requestBackoff()/reportHealthyResponse() calls for out-of-order detection.
    uint64_t m_nextSequence {0};
    // Shared backoff for "pause before the next send" (processor exception or requestBackoff()).
    // Guarded by m_backoffStateMutex, not atomic: reportHealthyResponse()/requestBackoff() can call
    // into it from the response logger's thread(s), concurrently with dispatch()'s nextDelay().
    std::mutex m_backoffStateMutex;
    IndexerExponentialBackoff m_backoff;
    bool m_externalBackoffPending {false};
    uint64_t m_lastReportedSequence {0};

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
