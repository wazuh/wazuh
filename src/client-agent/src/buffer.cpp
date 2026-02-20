/**
 * @file buffer.cpp
 * @brief C++17 implementation of the anti-flooding event buffer.
 *
 * Replaces buffer.c. Uses std::mutex / std::condition_variable
 * instead of pthreads.
 *
 * Copyright (C) 2015, Wazuh Inc.
 */

#include "event_buffer.hpp"

extern "C"
{
#include "sendmsg.h"
}

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <ctime>

#ifdef WIN32
#include <windows.h>
#include <winsock2.h>
#endif

namespace agentd
{

    // ── Singleton ────────────────────────────────────────────────────────

    EventBuffer& EventBuffer::instance()
    {
        static EventBuffer inst;
        return inst;
    }

    // ── Init ─────────────────────────────────────────────────────────────

    void EventBuffer::init()
    {
        if (!buffer_)
        {
            buffer_ =
                static_cast<BufferedMessage*>(calloc(static_cast<size_t>(agt->buflength) + 1, sizeof(BufferedMessage)));
            if (!buffer_)
            {
                merror_exit(MEM_ERROR, errno, strerror(errno));
            }
        }

        warn_level_ = getDefine_Int("agent", "warn_level", 1, 100);
        normal_level_ = getDefine_Int("agent", "normal_level", 0, warn_level_ - 1);
        tolerance_ = getDefine_Int("agent", "tolerance", 0, 600);

        if (tolerance_ == 0)
        {
            mwarn(TOLERANCE_TIME);
        }

        head_ = 0;
        tail_ = 0;
        state_ = NORMAL;
        flags_ = {};

        mdebug1("Agent buffer created.");
    }

    // ── Append ───────────────────────────────────────────────────────────

    int EventBuffer::append(const char* msg, ssize_t msg_len)
    {
        std::lock_guard<std::mutex> lock(mutex_);

        // Check level transitions upward
        switch (state_)
        {
            case NORMAL:
                if (isFull())
                {
                    flags_.full = 1;
                    state_ = FULL;
                    flood_start_ = std::time(nullptr);
                }
                else if (isWarnLevel())
                {
                    state_ = WARNING;
                    flags_.warn = 1;
                }
                break;
            case WARNING:
                if (isFull())
                {
                    flags_.full = 1;
                    state_ = FULL;
                    flood_start_ = std::time(nullptr);
                }
                break;
            case FULL:
                flood_end_ = std::time(nullptr);
                if (flood_end_ - flood_start_ >= tolerance_)
                {
                    state_ = FLOOD;
                    flags_.flood = 1;
                }
                break;
            case FLOOD: break;
            default: break;
        }

        w_agentd_state_update(INCREMENT_MSG_COUNT, nullptr);

        if (isFull())
        {
            mdebug2("Unable to store new packet: Buffer is full.");
            return -1;
        }

        size_t size_to_alloc;
        if (msg_len < 0)
        {
            size_to_alloc = std::strlen(msg) + 1;
        }
        else
        {
            size_to_alloc = static_cast<size_t>(msg_len);
        }

        buffer_[head_].data = malloc(size_to_alloc);
        if (!buffer_[head_].data)
        {
            merror_exit(MEM_ERROR, errno, strerror(errno));
        }
        std::memcpy(buffer_[head_].data, msg, size_to_alloc);
        buffer_[head_].size = size_to_alloc;

        advance(head_);
        cond_not_empty_.notify_one();

        return 0;
    }

    // ── Dispatch loop ────────────────────────────────────────────────────

    void EventBuffer::dispatch()
    {
        char flood_msg[OS_MAXSTR];
        char full_msg[OS_MAXSTR];
        char warn_msg[OS_MAXSTR];
        char normal_msg[OS_MAXSTR];
        char warn_str[OS_SIZE_2048];
        struct timespec ts0 {};
        struct timespec ts1 {};

        while (true)
        {
            gettime(&ts0);

            {
                std::unique_lock<std::mutex> lock(mutex_);
                cond_not_empty_.wait(lock, [this] { return !isEmpty() || !agt->buffer; });

                if (!agt->buffer)
                {
                    minfo("Dispatch buffer thread received stop signal. Exiting.");
                    break;
                }

                // Check level transitions downward
                switch (state_)
                {
                    case NORMAL: break;
                    case WARNING:
                        if (isNormalLevel())
                        {
                            state_ = NORMAL;
                            flags_.normal = 1;
                        }
                        break;
                    case FULL: [[fallthrough]];
                    case FLOOD:
                        if (isBelowWarn())
                            state_ = WARNING;
                        if (isNormalLevel())
                        {
                            state_ = NORMAL;
                            flags_.normal = 1;
                        }
                        break;
                    default: break;
                }
            }

            // Copy message under lock, then release
            BufferedMessage msg_to_dispatch;
            unsigned int original_tail;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                msg_to_dispatch = buffer_[tail_];
                original_tail = static_cast<unsigned int>(tail_);
                advance(tail_);
            }

            // Send status messages (outside lock)
            if (flags_.warn)
            {
                flags_.warn = 0;
                mwarn(WARN_BUFFER, warn_level_);
                snprintf(warn_str, OS_SIZE_2048, OS_WARN_BUFFER, warn_level_);
                snprintf(warn_msg, OS_MAXSTR, "%c:%s:%s", LOCALFILE_MQ, "wazuh-agent", warn_str);
                send_msg(warn_msg, -1);
            }

            if (flags_.full)
            {
                flags_.full = 0;
                mwarn(FULL_BUFFER);
                snprintf(full_msg, OS_MAXSTR, "%c:%s:%s", LOCALFILE_MQ, "wazuh-agent", OS_FULL_BUFFER);
                send_msg(full_msg, -1);
            }

            if (flags_.flood)
            {
                flags_.flood = 0;
                mwarn(FLOODED_BUFFER);
                snprintf(flood_msg, OS_MAXSTR, "%c:%s:%s", LOCALFILE_MQ, "wazuh-agent", OS_FLOOD_BUFFER);
                send_msg(flood_msg, -1);
            }

            if (flags_.normal)
            {
                flags_.normal = 0;
                minfo(NORMAL_BUFFER, normal_level_);
                snprintf(normal_msg, OS_MAXSTR, "%c:%s:%s", LOCALFILE_MQ, "wazuh-agent", OS_NORMAL_BUFFER);
                send_msg(normal_msg, -1);
            }

            os_wait();

            if (msg_to_dispatch.data != nullptr)
            {
                send_msg(static_cast<const char*>(msg_to_dispatch.data), static_cast<ssize_t>(msg_to_dispatch.size));
                ::free(msg_to_dispatch.data);
                buffer_[original_tail].data = nullptr;
                buffer_[original_tail].size = 0;
            }

            gettime(&ts1);
            time_sub(&ts1, &ts0);

            if (ts1.tv_sec >= 0)
            {
                delay(&ts1);
            }
        }
    }

    // ── EPS delay ────────────────────────────────────────────────────────

    void EventBuffer::delay(struct timespec* ts_loop)
    {
        long interval_ns = 1000000000L / agt->events_persec;
        struct timespec ts_timeout = {interval_ns / 1000000000L, interval_ns % 1000000000L};
        time_sub(&ts_timeout, ts_loop);

        if (ts_timeout.tv_sec >= 0)
        {
            nanosleep(&ts_timeout, nullptr);
        }
    }

    // ── Get buffer length ────────────────────────────────────────────────

    int EventBuffer::getLength()
    {
        if (agt->buffer <= 0)
        {
            return -1;
        }

        int retval;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            retval = (head_ - tail_) % (agt->buflength + 1);
        }

        return (retval < 0) ? (retval + agt->buflength + 1) : retval;
    }

    // ── Free buffer ──────────────────────────────────────────────────────

    void EventBuffer::free(unsigned int current_capacity)
    {
        std::lock_guard<std::mutex> lock(mutex_);

        if (buffer_ == nullptr || current_capacity == 0)
        {
            mwarn("Buffer is already unallocated or invalid. Skipping free operation.");
            return;
        }

        mdebug2("Freeing the client-buffer.");
        for (unsigned int k = 0; k <= current_capacity; k++)
        {
            ::free(buffer_[k].data);
            buffer_[k].data = nullptr;
        }

        ::free(buffer_);
        buffer_ = nullptr;

        agt->buflength = 0;
        head_ = 0;
        tail_ = 0;

        // Signal to end dispatch thread
        cond_not_empty_.notify_one();

        minfo("Client buffer freed successfully.");
    }

    // ── Resize buffer ────────────────────────────────────────────────────

    int EventBuffer::resize(unsigned int current_capacity, unsigned int desired_capacity)
    {
        if (desired_capacity == 0)
        {
            merror("Invalid new buffer capacity requested: %u.", desired_capacity);
            return -1;
        }

        if (desired_capacity == current_capacity)
        {
            return 0;
        }

        int tmp_count = getLength();
        if (tmp_count < 0)
        {
            merror("Failed to get buffer length.");
            return -1;
        }

        auto agent_msg_count = static_cast<unsigned int>(tmp_count);
        if (agent_msg_count > (current_capacity + 1))
        {
            merror("Agent message count (%u) exceeds current buffer capacity (%u).",
                   agent_msg_count,
                   current_capacity + 1);
            return -1;
        }

        std::lock_guard<std::mutex> lock(mutex_);

        auto* temp_buffer =
            static_cast<BufferedMessage*>(calloc(static_cast<size_t>(desired_capacity) + 1, sizeof(BufferedMessage)));
        if (!temp_buffer)
        {
            merror_exit(MEM_ERROR, errno, strerror(errno));
        }

        if (desired_capacity > current_capacity)
        {
            // Growing
            if (tail_ < head_)
            {
                mdebug2("Copying contiguous data to new buffer. Count: %u events, "
                        "tail: %d, head: %d\n",
                        agent_msg_count,
                        tail_,
                        head_);
                std::memcpy(temp_buffer, &buffer_[tail_], agent_msg_count * sizeof(BufferedMessage));
            }
            else
            {
                int first_part = (static_cast<int>(current_capacity) - tail_) + 1;
                mdebug2("Wrapped buffer detected. Copying in two parts:\n");
                mdebug2("  Part 1: %d bytes from old[tail=%d] -> new[0]\n", first_part, tail_);
                mdebug2("  Part 2: %d bytes from old[0] -> new[%d]\n", head_, first_part);
                std::memcpy(temp_buffer, &buffer_[tail_], static_cast<size_t>(first_part) * sizeof(BufferedMessage));
                std::memcpy(temp_buffer + first_part, buffer_, static_cast<size_t>(head_) * sizeof(BufferedMessage));
            }
        }
        else
        {
            // Shrinking
            mwarn("Shrinking client buffer from %u to %u (messages: %u).",
                  current_capacity,
                  desired_capacity,
                  agent_msg_count);

            unsigned int retained = (agent_msg_count < desired_capacity) ? agent_msg_count : desired_capacity;

            for (unsigned int k = 0; k < retained; k++)
            {
                unsigned int old_idx = (static_cast<unsigned int>(tail_) + k) % (current_capacity + 1);
                if (buffer_[old_idx].data != nullptr)
                {
                    temp_buffer[k] = buffer_[old_idx];
                    buffer_[old_idx].data = nullptr;
                    buffer_[old_idx].size = 0;
                    mdebug2("Moving message from old[%u] to new[%u] (ptr: %p)", old_idx, k, temp_buffer[k].data);
                }
            }

            minfo("Successfully copied %u messages to the new buffer.", retained);

            for (unsigned int idx = 0; idx <= current_capacity; idx++)
            {
                if (buffer_[idx].data != nullptr)
                {
                    mdebug2("Freeing buffer[%u] (ptr: %p)\n", idx, buffer_[idx].data);
                    ::free(buffer_[idx].data);
                }
            }

            agent_msg_count = retained;
            w_agentd_state_update(RESET_MSG_COUNT_ON_SHRINK, &agent_msg_count);
        }

        tail_ = 0;
        head_ = static_cast<int>(agent_msg_count);
        ::free(buffer_);
        buffer_ = temp_buffer;

        minfo("Client buffer resized from %u to %u elements.", current_capacity, desired_capacity);
        return 0;
    }

} // namespace agentd

// =====================================================================
//  extern "C" trampolines + globals
// =====================================================================

extern "C"
{

    int warn_level;
    int normal_level;
    int tolerance;

    void buffer_init()
    {
        auto& b = agentd::EventBuffer::instance();
        b.init();
        warn_level = b.warnLevel();
        normal_level = b.normalLevel();
        tolerance = b.toleranceVal();
    }

    int buffer_append(const char* msg, ssize_t msg_len)
    {
        return agentd::EventBuffer::instance().append(msg, msg_len);
    }

#ifdef WIN32
    DWORD WINAPI dispatch_buffer(__attribute__((unused)) LPVOID arg)
    {
        agentd::EventBuffer::instance().dispatch();
        return 0;
    }
#else
    void* dispatch_buffer(__attribute__((unused)) void* arg)
    {
        agentd::EventBuffer::instance().dispatch();
        return nullptr;
    }
#endif

    int w_agentd_get_buffer_lenght()
    {
        return agentd::EventBuffer::instance().getLength();
    }

    void w_agentd_buffer_free(unsigned int current_capacity)
    {
        agentd::EventBuffer::instance().free(current_capacity);
    }

    int w_agentd_buffer_resize(unsigned int current_capacity, unsigned int desired_capacity)
    {
        return agentd::EventBuffer::instance().resize(current_capacity, desired_capacity);
    }

} // extern "C"
