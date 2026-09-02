#pragma once

#include <chrono>

namespace wazuh::container_instances
{

    /// Plain value injected wherever a bounded retry loop runs (watch reconnect,
    /// cold-cache resolution, docker stream resume). One instance per use site.
    struct RetryPolicy
    {
        int maxAttempts {3};
        std::chrono::milliseconds initialBackoff {100};
        std::chrono::milliseconds maxBackoff {300};

        [[nodiscard]] std::chrono::milliseconds backoffFor(int attempt) const
        {
            auto delay = initialBackoff;
            for (int i = 1; i < attempt && delay < maxBackoff; ++i)
            {
                delay *= 2;
            }
            return delay < maxBackoff ? delay : maxBackoff;
        }
    };

} // namespace wazuh::container_instances
