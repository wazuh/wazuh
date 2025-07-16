#pragma once

#include <isca_policy.hpp>
#include <sca_policy_check.hpp>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <functional>
#include <memory>
#include <string>
#include <vector>

struct Check
{
    std::optional<std::string> id;
    std::string condition;
    std::vector<std::unique_ptr<IRuleEvaluator>> rules;
};

class SCAPolicy : public ISCAPolicy
{
public:
    /// @brief Constructor
    explicit SCAPolicy(std::string id, Check requirements, std::vector<Check> checks);

    /// @brief Move constructor
    SCAPolicy(SCAPolicy&& other) noexcept;

    /// @copydoc ISCAPolicy::Run
    void
    Run(std::time_t scanInterval,
        bool scanOnStart,
        std::function<void(const std::string&, const std::string&, const std::string&)> reportCheckResult,
        std::function<void(std::chrono::milliseconds)> wait) override;

    /// @copydoc ISCAPolicy::Stop
    void Stop() override;

private:
    /// @brief Runs the policy checks
    /// @param reportCheckResult Function to report check result
    void Scan(const std::function<void(const std::string&, const std::string&, const std::string&)>& reportCheckResult);

    std::string m_id;
    Check m_requirements;
    std::vector<Check> m_checks;
    std::atomic<bool> m_keepRunning {true};
    std::atomic<bool> m_scanInProgress {false};
};
