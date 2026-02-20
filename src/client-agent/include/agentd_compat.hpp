/**
 * @file agentd_compat.hpp
 * @brief C++ compatibility header for wazuh-agentd.
 *
 * Wraps all external C headers consumed by the agent daemon in
 * `extern "C"` blocks so that C++ translation units can link
 * against the C-compiled libraries without name-mangling issues.
 *
 * Every .cpp file in client-agent should include this header
 * instead of including the C headers directly.
 */

#ifndef AGENTD_COMPAT_HPP
#define AGENTD_COMPAT_HPP

// ── C++ standard library headers (include BEFORE C headers) ──────────
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

// ── External C headers wrapped for C++ linkage ───────────────────────
extern "C"
{

// Wazuh shared library
#include "shared.h"

// Networking
#include "os_net.h"

// Security / encryption
#include "sec.h"

// Configuration
#include "client-config.h"
#include "module_limits.h"

// cJSON
#include "cJSON.h"

// Agent metadata
#include "metadata_provider.h"

// Logging
#include "log_rotate.h"

// Crypto
#include "md5_op.h"

// Wazuh modules
#include "wmodules.h"

// Request operations
#include <request_op.h>

} // extern "C"

// ── RAII wrapper for cJSON ───────────────────────────────────────────
struct CJsonDeleter
{
    void operator()(cJSON* p) const noexcept
    {
        if (p)
            cJSON_Delete(p);
    }
};
using CJsonPtr = std::unique_ptr<cJSON, CJsonDeleter>;

// ── Convenience: make a CJsonPtr from a raw cJSON* (takes ownership) ─
inline CJsonPtr make_cjson(cJSON* raw) noexcept
{
    return CJsonPtr(raw);
}

#endif // AGENTD_COMPAT_HPP
