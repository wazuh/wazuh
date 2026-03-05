#ifndef _RETRY_UTILS_HPP
#define _RETRY_UTILS_HPP

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

template<typename Func>
decltype(auto) executeWithRetry(Func&& operation,
                                std::string_view operationName,
                                std::string_view componentName,
                                std::size_t maxAttempts,
                                std::size_t waitSeconds)
{
    for (std::size_t attempt = 1; attempt <= maxAttempts; ++attempt)
    {
        try
        {
            return operation();
        }
        catch (const std::exception& e)
        {
            LOG_WARNING_L(operationName.data(),
                          "[{}::{}] Attempt {}/{}: {}",
                          componentName,
                          operationName,
                          attempt,
                          maxAttempts,
                          e.what());
            if (attempt < maxAttempts)
            {
                std::this_thread::sleep_for(std::chrono::seconds(waitSeconds));
            }
            else
            {
                throw std::runtime_error(fmt::format(
                    "{}::{} failed after {} attempts: {}", componentName, operationName, maxAttempts, e.what()));
            }
        }
    }

    throw std::runtime_error(fmt::format("Unreachable code in {}::{}", componentName, operationName));
}

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

#endif // _RETRY_UTILS_HPP
