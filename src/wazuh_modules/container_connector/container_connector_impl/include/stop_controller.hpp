#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>

namespace wazuh::container_connector {

/// @brief Cooperative cancellation primitive shared across all components of the module.
///
/// One instance is owned by ContainerConnectorImpl and passed by std::shared_ptr to every
/// component (K8s client, watcher, IPC server, …). Components must:
///   - Replace any unconditional sleep with WaitFor(duration).
///   - Check IsStopRequested() before starting a new unit of work.
///   - Implement their own component-specific wake-up for blocking syscalls
///     (e.g. close a listening socket, signal an eventfd) when RequestStop is observed.
///
/// Once RequestStop() is called the controller is sticky — there is no way back to running.
/// Module restart, if ever needed, is achieved by destroying the impl and creating a new one.
class StopController final
{
public:
    StopController() = default;
    ~StopController() = default;

    StopController(const StopController&) = delete;
    StopController& operator=(const StopController&) = delete;
    StopController(StopController&&) = delete;
    StopController& operator=(StopController&&) = delete;

    void RequestStop() noexcept
    {
        {
            std::lock_guard<std::mutex> lk(mutex_);
            stopping_.store(true, std::memory_order_release);
        }
        cv_.notify_all();
    }

    bool IsStopRequested() const noexcept
    {
        return stopping_.load(std::memory_order_acquire);
    }

    /// @brief Wait up to `duration` for a stop request.
    /// @return true if the wait timed out (no stop), false if a stop was observed.
    template <typename Rep, typename Period>
    bool WaitFor(std::chrono::duration<Rep, Period> duration)
    {
        std::unique_lock<std::mutex> lk(mutex_);
        return !cv_.wait_for(lk, duration,
                             [this] { return stopping_.load(std::memory_order_acquire); });
    }

private:
    mutable std::mutex      mutex_;
    std::condition_variable cv_;
    std::atomic<bool>       stopping_{false};
};

} // namespace wazuh::container_connector
