#pragma once

#include <cstdint>
#include <functional>
#include <string>

namespace wazuh::container_instances
{

    enum class LogLevel : std::uint8_t
    {
        debugVerbose,
        debug,
        info,
        warn,
        error
    };

    /// Injected logging sink. The C API layer maps LogLevel onto the agent's
    /// modules_log_level_t and routes through the wm log callback; tests capture it.
    using Logger = std::function<void(LogLevel, const std::string&)>;

} // namespace wazuh::container_instances
