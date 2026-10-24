// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef _API_EVENT_IDENTITY_WARNING_GATE_HPP
#define _API_EVENT_IDENTITY_WARNING_GATE_HPP

#include <atomic>
#include <chrono>
#include <cstdint>
#include <limits>

namespace api::event
{
/// One warning per 90 seconds across the threads sharing an ingress handler.
class IdentityWarningGate
{
public:
    bool allow(std::chrono::steady_clock::time_point now) noexcept
    {
        const auto ticks = now.time_since_epoch().count();
        constexpr auto interval =
            std::chrono::duration_cast<std::chrono::steady_clock::duration>(std::chrono::seconds(90)).count();
        auto next = m_next.load(std::memory_order_relaxed);
        while (ticks >= next)
        {
            if (m_next.compare_exchange_weak(next, ticks + interval, std::memory_order_relaxed))
            {
                return true;
            }
        }
        return false;
    }

private:
    std::atomic<std::chrono::steady_clock::rep> m_next {std::numeric_limits<std::chrono::steady_clock::rep>::min()};
};
} // namespace api::event

#endif // _API_EVENT_IDENTITY_WARNING_GATE_HPP
