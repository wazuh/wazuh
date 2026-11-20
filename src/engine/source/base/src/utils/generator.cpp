// SPDX-License-Identifier: AGPL-3.0-or-later
#include <algorithm>
#include <array>
#include <atomic>
#include <climits>
#include <cstring>
#include <limits>
#include <mutex>
#include <stdexcept>

#include <pthread.h>

#include <openssl/err.h>
#include <openssl/rand.h>

#include "utils/generator.hpp"
#include "utils/timeUtils.hpp"

namespace base::utils::generators
{
namespace
{
/// Random source behind fillRandom(); fillRandom() is its only reader.
std::atomic<detail::RandBytesFn> g_randBytes {&RAND_bytes};

/// Size, in bytes, of a document identifier before encoding (8-byte clock + prefix).
constexpr size_t DOC_ID_RAW_SIZE = 8 + DOC_ID_PREFIX_SIZE;

static_assert((DOC_ID_RAW_SIZE * 8 + 5) / 6 == DOC_ID_LENGTH, "DOC_ID_LENGTH must match the unpadded base64url size");

/// Random bytes behind one UUID version 4 (122 random bits once the version and variant bits are set).
constexpr size_t UUID_V4_RAW_SIZE = 16;

/**
 * @brief Per-thread state of generateDocId().
 *
 * Trivial and constant-initialized, so the thread_local needs no dynamic initialization and onForkChild() can
 * touch it safely.
 */
struct DocIdState
{
    bool init;
    uint8_t prefix[DOC_ID_PREFIX_SIZE];
    int64_t last;
};

thread_local DocIdState t_state {};

/// Size, in bytes, of the per-thread buffer of random bytes behind generateUUIDv4() (256 identifiers per refill).
constexpr size_t UUID_BUFFER_SIZE = 4096;

static_assert(UUID_BUFFER_SIZE % UUID_V4_RAW_SIZE == 0, "the buffer must hold a whole number of identifiers");

/// Per-thread state of generateUUIDv4(): trivial and constant-initialized, so that onForkChild() can reset it.
/// t_uuidPos == UUID_BUFFER_SIZE means that the buffer holds nothing usable.
thread_local std::array<uint8_t, UUID_BUFFER_SIZE> t_uuidBuffer {};
thread_local size_t t_uuidPos = UUID_BUFFER_SIZE;

std::once_flag g_atforkOnce;

/// Child-side fork handler: forces a new doc-id prefix and new UUID state in the child (async-signal-safe: stores
/// only).
void onForkChild()
{
    t_state.init = false;
    t_uuidPos = UUID_BUFFER_SIZE;
}

/**
 * @brief Registers onForkChild() once per process.
 *
 * @throws std::runtime_error if the handler cannot be registered; the once_flag is left unconsumed, so the next call
 *         retries.
 */
void ensureForkHandler()
{
    std::call_once(g_atforkOnce,
                   []()
                   {
                       if (pthread_atfork(nullptr, nullptr, &onForkChild) != 0)
                       {
                           throw std::runtime_error("generators: cannot register the fork handler");
                       }
                   });
}

/**
 * @brief Writes 16 random bytes as a UUID version 4: sets the version (4) and variant (10xx) bits, then encodes the
 * bytes as lowercase hexadecimal in the 8-4-4-4-12 layout.
 */
std::string formatUuidV4(uint8_t bytes[UUID_V4_RAW_SIZE])
{
    constexpr char hexDigits[] = "0123456789abcdef";

    bytes[6] = static_cast<uint8_t>((bytes[6] & 0x0F) | 0x40);
    bytes[8] = static_cast<uint8_t>((bytes[8] & 0x3F) | 0x80);

    std::string out(UUID_V4_LENGTH, '-');
    size_t o = 0;
    for (size_t i = 0; i < UUID_V4_RAW_SIZE; ++i)
    {
        if (o == 8 || o == 13 || o == 18 || o == 23)
        {
            ++o;
        }
        out[o++] = hexDigits[bytes[i] >> 4];
        out[o++] = hexDigits[bytes[i] & 0x0F];
    }
    return out;
}

/**
 * @brief Shared core of DocIdGenerator::next() and generateDocId().
 *
 * t = max(now, last + 1); if last is already INT64_MAX the increment would overflow, so t = max(now, last) = last
 * (the value repeats; unreachable in practice: year 2262).
 * Layout: BE64(t) || prefix[12], encoded as unpadded base64url (27 characters).
 */
std::string encodeDocId(int64_t& last, const uint8_t* prefix, int64_t now)
{
    constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    const auto next = last == std::numeric_limits<int64_t>::max() ? last : last + 1;
    const auto t = std::max(now, next);
    last = t;

    uint8_t raw[DOC_ID_RAW_SIZE];
    const auto ut = static_cast<uint64_t>(t);
    for (size_t i = 0; i < 8; ++i)
    {
        raw[i] = static_cast<uint8_t>(ut >> (56 - 8 * i));
    }
    std::memcpy(raw + 8, prefix, DOC_ID_PREFIX_SIZE);

    std::string out(DOC_ID_LENGTH, '\0');
    size_t o = 0;
    size_t i = 0;
    for (; i + 3 <= DOC_ID_RAW_SIZE; i += 3)
    {
        const uint32_t v = (uint32_t(raw[i]) << 16) | (uint32_t(raw[i + 1]) << 8) | uint32_t(raw[i + 2]);
        out[o++] = alphabet[(v >> 18) & 0x3F];
        out[o++] = alphabet[(v >> 12) & 0x3F];
        out[o++] = alphabet[(v >> 6) & 0x3F];
        out[o++] = alphabet[v & 0x3F];
    }
    // 20 = 6 * 3 + 2: two trailing bytes give three characters, no padding.
    static_assert(DOC_ID_RAW_SIZE % 3 == 2, "the tail encoding below assumes two remaining bytes");
    const uint32_t v = (uint32_t(raw[i]) << 16) | (uint32_t(raw[i + 1]) << 8);
    out[o++] = alphabet[(v >> 18) & 0x3F];
    out[o++] = alphabet[(v >> 12) & 0x3F];
    out[o++] = alphabet[(v >> 6) & 0x3F];

    return out;
}
} // namespace

void fillRandom(uint8_t* out, size_t n)
{
    if (n > static_cast<size_t>(INT_MAX))
    {
        throw std::runtime_error("fillRandom: requested size exceeds INT_MAX");
    }
    if (n == 0)
    {
        return;
    }

    const auto source = g_randBytes.load();
    ERR_clear_error(); // Report only what this call leaves in the thread's error queue.
    if (source(out, static_cast<int>(n)) != 1)
    {
        char err[256] = {};
        ERR_error_string_n(ERR_peek_last_error(), err, sizeof(err));
        ERR_clear_error();
        throw std::runtime_error(std::string("fillRandom: the random source failed: ") + err);
    }
}

std::string generateDocId()
{
    auto& state = t_state;
    if (!state.init)
    {
        ensureForkHandler();

        uint8_t tmp[DOC_ID_PREFIX_SIZE];
        fillRandom(tmp, sizeof(tmp));
        std::memcpy(state.prefix, tmp, sizeof(tmp));
        state.init = true;
    }

    return encodeDocId(state.last, state.prefix, base::utils::time::systemEpochNanos());
}

std::string generateUUIDv4()
{
    if (t_uuidPos == UUID_BUFFER_SIZE)
    {
        ensureForkHandler();

        // On failure t_uuidPos stays at the end, so the unspecified content of the buffer is never used.
        fillRandom(t_uuidBuffer.data(), UUID_BUFFER_SIZE);
        t_uuidPos = 0;
    }

    uint8_t bytes[UUID_V4_RAW_SIZE];
    std::memcpy(bytes, t_uuidBuffer.data() + t_uuidPos, UUID_V4_RAW_SIZE);
    t_uuidPos += UUID_V4_RAW_SIZE;
    return formatUuidV4(bytes);
}

namespace detail
{
RandBytesFn exchangeRandBytesForTesting(RandBytesFn fn) noexcept
{
    return g_randBytes.exchange(fn ? fn : &RAND_bytes);
}

DocIdGenerator::DocIdGenerator(const std::array<uint8_t, DOC_ID_PREFIX_SIZE>& prefix) noexcept
    : m_prefix(prefix)
    , m_last(0)
{
}

std::string DocIdGenerator::next(int64_t nowNs)
{
    return encodeDocId(m_last, m_prefix.data(), nowNs);
}
} // namespace detail

} // namespace base::utils::generators
