#pragma once

#include <chrono>
#include <ctime>
#include <functional>
#include <string>

class ISCAPolicy
{
public:
    /// @brief Destructor
    virtual ~ISCAPolicy() = default;

    /// @brief Runs the policy check
    /// @param scanInterval Scan interval in milliseconds
    /// @param scanOnStart Scan on start
    /// @param reportCheckResult Function to report check result
    /// @param wait Function to wait for the next scan
    virtual void
    Run(std::time_t scanInterval,
        bool scanOnStart,
        std::function<void(const std::string&, const std::string&, const std::string&)> reportCheckResult,
        std::function<void(std::chrono::milliseconds)> wait) = 0;

    /// @brief Stops the policy check
    virtual void Stop() = 0;
};
