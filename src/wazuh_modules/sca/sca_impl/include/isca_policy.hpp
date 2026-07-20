#pragma once

#include <functional>
#include <string>

struct CheckResult
{
    std::string policyId;
    std::string checkId;
    std::string result;
    std::string reason;
};

class ISCAPolicy
{
    public:
        /// @brief Destructor
        virtual ~ISCAPolicy() = default;

        /// @brief Runs the policy check
        /// @param reportCheckResult Function to report check result
        virtual void Run(std::function<void(const CheckResult&)> reportCheckResult) = 0;

        /// @brief Stops the policy check
        virtual void Stop() = 0;
};
