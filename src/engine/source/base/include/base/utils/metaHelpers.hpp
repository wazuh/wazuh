#ifndef META_HELPERS_HPP
#define META_HELPERS_HPP

#include <atomic>
#include <chrono>
#include <cstddef>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

#include <fmt/format.h>

#include <base/logging.hpp>

namespace base::utils
{
/**
 * @brief Execute an operation with retry logic and abort support
 *
 * This function attempts to execute the provided operation and retries it if an exception is thrown. It logs each
 * attempt and waits for a specified duration between retries. The shutdownRequested flag is checked
 * before each retry attempt and during the wait between retries (split into 1-second intervals for responsive
 * cancellation).
 * @tparam Func Callable type that performs the operation
 * @param operation The operation to execute
 * @param componentOperationName Name of the component operation for logging purposes
 * @param message Description of the operation for logging purposes
 * @param maxAttempts Maximum number of retry attempts, cannot be zero (will default to 1 attempt)
 * @param waitSeconds Seconds to wait between retries, cannot be zero (will default to 1 second)
 * @param shutdownRequested Atomic flag that signals abort when true
 * @return decltype(auto) Result of the operation
 * @throw std::runtime_error if aborted, or if all retry attempts fail
 */
template<typename Func>
decltype(auto) executeWithRetry(Func&& operation,
                                const std::string& componentOperationName,
                                std::string_view message,
                                std::size_t maxAttempts,
                                std::size_t waitSeconds,
                                const std::atomic<bool>& shutdownRequested)
{
    // Ensure at least 1 second wait to avoid tight loop
    waitSeconds = waitSeconds == 0 ? 1 : waitSeconds;
    // Ensure at least 1 attempt to execute the operation
    maxAttempts = maxAttempts == 0 ? 1 : maxAttempts;
    for (std::size_t attempt = 1; attempt <= maxAttempts; ++attempt)
    {
        if (shutdownRequested.load(std::memory_order_relaxed))
        {
            throw std::runtime_error(
                fmt::format("{}::{} aborted before attempt {}", message, componentOperationName, attempt));
        }

        try
        {
            return operation();
        }
        catch (const std::exception& e)
        {
            LOG_WARNING_L(componentOperationName.c_str(),
                          "[{}] {} - Attempt {}/{}: {}",
                          componentOperationName,
                          message,
                          attempt,
                          maxAttempts,
                          e.what());
            if (attempt < maxAttempts)
            {
                // Split sleep into 1-second chunks for responsive abort
                for (std::size_t s = 0; s < waitSeconds; ++s)
                {
                    if (shutdownRequested.load(std::memory_order_relaxed))
                    {
                        throw std::runtime_error(fmt::format("{}::{} aborted during retry wait (attempt {})",
                                                             message,
                                                             componentOperationName,
                                                             attempt));
                    }
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                }
            }
            else
            {
                throw std::runtime_error(fmt::format(
                    "{}::{} failed after {} attempts: {}", message, componentOperationName, maxAttempts, e.what()));
            }
        }
    }

    throw std::runtime_error(fmt::format("Unreachable code in {}::{}", message, componentOperationName));
}

/**
 * @brief Execute an operation with retry logic and no abort support
 *
 * This overload keeps call sites simple when no cancellation flag exists.
 */
template<typename Func>
decltype(auto) executeWithRetry(Func&& operation,
                                const std::string& componentOperationName,
                                std::string_view message,
                                std::size_t maxAttempts,
                                std::size_t waitSeconds)
{
    static const std::atomic<bool> kNeverShutdown {false};
    return executeWithRetry(std::forward<Func>(operation),
                            componentOperationName,
                            message,
                            maxAttempts,
                            waitSeconds,
                            kNeverShutdown);
}

/**
 * @brief Locks a weak pointer and returns a shared pointer.
 *
 * @tparam T Type of the resource
 * @param weakPtr Weak pointer to lock
 * @param resourceName Name of the resource for error messages
 * @return std::shared_ptr<T> Shared pointer to the resource
 * @throw std::runtime_error if the resource is not available
 */
template<typename T>
std::shared_ptr<T> lockWeakPtr(const std::weak_ptr<T>& weakPtr, std::string_view resourceName)
{
    auto sharedPtr = weakPtr.lock();
    if (!sharedPtr)
    {
        throw std::runtime_error(fmt::format("{} resource is not available", resourceName));
    }
    return sharedPtr;
}

} // namespace base::utils

#endif // META_HELPERS_HPP
