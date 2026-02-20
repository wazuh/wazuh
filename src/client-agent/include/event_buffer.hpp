/**
 * @file event_buffer.hpp
 * @brief C++17 replacement for buffer.c
 *
 * Anti-flooding circular buffer for agent events. Uses std::mutex
 * and std::condition_variable instead of pthreads.
 *
 * Copyright (C) 2015, Wazuh Inc.
 */

#ifndef AGENTD_EVENT_BUFFER_HPP
#define AGENTD_EVENT_BUFFER_HPP

#include "agentd_compat.hpp"

extern "C"
{
#include "agentd.h"
#include "state.h"
}

namespace agentd
{

    /**
     * @brief A single message stored in the circular buffer.
     */
    struct BufferedMessage
    {
        void* data {nullptr};
        size_t size {0};
    };

    /**
     * @brief Anti-flooding circular event buffer.
     *
     * Replaces the C buffer.c implementation. Manages a dynamically
     * allocated ring-buffer of messages, rate-limiting dispatch to
     * the manager.
     */
    class EventBuffer
    {
    public:
        EventBuffer() = default;
        ~EventBuffer() = default;

        EventBuffer(const EventBuffer&) = delete;
        EventBuffer& operator=(const EventBuffer&) = delete;

        /** Allocate buffer and read internal config. */
        void init();

        /** Append a message to the buffer. Returns 0 on success, -1 if full. */
        int append(const char* msg, ssize_t msg_len);

        /** Dispatch loop: sends buffered messages to the manager (never returns normally). */
        void dispatch();

        /** Get current number of buffered messages, or -1 if buffer disabled. */
        int getLength();

        /** Free the buffer and signal dispatch thread to exit. */
        void free(unsigned int current_capacity);

        /** Resize the buffer (grow or shrink). */
        int resize(unsigned int current_capacity, unsigned int desired_capacity);

        /** Access the singleton. */
        static EventBuffer& instance();

        // Config accessors for config.c globals
        int warnLevel() const noexcept
        {
            return warn_level_;
        }
        int normalLevel() const noexcept
        {
            return normal_level_;
        }
        int toleranceVal() const noexcept
        {
            return tolerance_;
        }

    private:
        // ── Buffer state check helpers ─────────────────────────────
        bool isFull() const
        {
            return (head_ + 1) % (agt->buflength + 1) == tail_;
        }

        bool isEmpty() const
        {
            return head_ == tail_;
        }

        float usageRatio() const
        {
            return static_cast<float>((head_ - tail_ + agt->buflength + 1) % (agt->buflength + 1)) /
                   static_cast<float>(agt->buflength);
        }

        bool isWarnLevel() const
        {
            return usageRatio() >= static_cast<float>(warn_level_) / 100.0f;
        }

        bool isBelowWarn() const
        {
            return usageRatio() <= static_cast<float>(warn_level_) / 100.0f;
        }

        bool isNormalLevel() const
        {
            return usageRatio() <= static_cast<float>(normal_level_) / 100.0f;
        }

        void advance(int& idx)
        {
            idx = (idx + 1) % (agt->buflength + 1);
        }

        /** EPS rate-limiter sleep. */
        void delay(struct timespec* ts_loop);

        // ── State ─────────────────────────────────────────────────
        std::mutex mutex_;
        std::condition_variable cond_not_empty_;

        BufferedMessage* buffer_ {nullptr};
        int head_ {0};  // write index (was 'i')
        int tail_ {0};  // read index  (was 'j')
        int state_ {0}; // NORMAL/WARNING/FULL/FLOOD

        int warn_level_ {0};
        int normal_level_ {0};
        int tolerance_ {0};

        std::time_t flood_start_ {0};
        std::time_t flood_end_ {0};

        struct
        {
            unsigned int full : 1;
            unsigned int warn : 1;
            unsigned int flood : 1;
            unsigned int normal : 1;
        } flags_ {};
    };

} // namespace agentd

#endif // AGENTD_EVENT_BUFFER_HPP
