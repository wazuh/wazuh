#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>

namespace wazuh::container_instances
{

    /// Cooperative cancellation primitive shared across all components of the module.
    ///
    /// One instance is owned by the facade and passed by reference to every component.
    /// Components must:
    ///   - Replace any unconditional sleep with waitFor(duration).
    ///   - Check isStopRequested() before starting a new unit of work.
    ///   - Implement their own wake-up for blocking syscalls (close a listening socket,
    ///     signal an eventfd, curl_multi_wakeup) when requestStop is observed.
    ///
    /// Once requestStop() is called the controller is sticky — there is no way back to
    /// running. Module restart is achieved by destroying the facade and creating a new one.
    class StopController final
    {
    public:
        StopController() = default;
        ~StopController() = default;

        StopController(const StopController&) = delete;
        StopController& operator=(const StopController&) = delete;
        StopController(StopController&&) = delete;
        StopController& operator=(StopController&&) = delete;

        void requestStop() noexcept
        {
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_stopping.store(true, std::memory_order_release);
            }
            m_cv.notify_all();
        }

        [[nodiscard]] bool isStopRequested() const noexcept
        {
            return m_stopping.load(std::memory_order_acquire);
        }

        /// Wait up to `duration` for a stop request.
        /// @return true if the wait timed out (no stop), false if a stop was observed.
        template<typename Rep, typename Period>
        [[nodiscard]] bool waitFor(std::chrono::duration<Rep, Period> duration) const
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            return !m_cv.wait_for(lock, duration, [this] { return m_stopping.load(std::memory_order_acquire); });
        }

    private:
        mutable std::mutex m_mutex;
        mutable std::condition_variable m_cv;
        std::atomic<bool> m_stopping {false};
    };

} // namespace wazuh::container_instances
