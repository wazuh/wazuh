// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef _BASE_GENERATORS_HPP
#define _BASE_GENERATORS_HPP

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <random>
#include <string>
#include <string_view>

/**
 * @brief Namespace for generators utility functions.
 *
 */

namespace base::utils::generators
{
constexpr size_t UUID_V4_LENGTH = 36;

/**
 * @brief Length, in characters, of an identifier returned by generateDocId().
 */
constexpr size_t DOC_ID_LENGTH = 27;

/**
 * @brief Size, in bytes, of the per-thread random prefix of a document identifier.
 */
constexpr size_t DOC_ID_PREFIX_SIZE = 12;

/**
 * @brief Fills a buffer with cryptographically secure random bytes (OpenSSL RAND_bytes).
 *
 * Thread-safe and fork-safe (OpenSSL reseeds its DRBG after fork). It never falls back to a weaker source.
 *
 * @param out Destination buffer (may be nullptr only when n is 0).
 * @param n Number of bytes to write.
 * @throws std::runtime_error if n exceeds INT_MAX (the source is not called) or if the source reports a failure
 *         (the message carries the OpenSSL error). On failure the content of the buffer is unspecified.
 */
void fillRandom(uint8_t* out, size_t n);

/**
 * @brief Generates a random UUID version 4 (thread-safe).
 *
 * 122 random bits from fillRandom() (one 16-byte call per identifier), version nibble 4 and variant bits 10,
 * formatted as 36 lowercase hexadecimal characters in the 8-4-4-4-12 layout.
 *
 * @throws std::runtime_error if the random source fails.
 */
std::string generateUUIDv4();

/**
 * @brief Generates a document identifier for an indexer write (thread-safe, lock-free).
 *
 * The 20 identifier bytes are the 8-byte big-endian value of a per-thread strictly increasing nanosecond clock
 * (max(systemEpochNanos(), last + 1)) followed by a 12-byte random prefix drawn once per thread with fillRandom().
 * They are encoded as unpadded base64url, so the result is always DOC_ID_LENGTH characters of [A-Za-z0-9_-].
 * The prefix is drawn again in a child process after fork().
 *
 * @throws std::runtime_error if the random source fails while drawing the prefix of the calling thread (the
 *         next call on that thread retries) or if the fork handler cannot be registered.
 */
std::string generateDocId();

namespace detail
{
/**
 * @brief Signature of the random source behind fillRandom() (the one of RAND_bytes).
 */
using RandBytesFn = int (*)(unsigned char*, int);

/**
 * @brief Test seam: replaces the random source used by fillRandom() and returns the previous one.
 *
 * Passing nullptr restores the default source (&RAND_bytes). Only tests call it.
 */
RandBytesFn exchangeRandBytesForTesting(RandBytesFn fn) noexcept;

/**
 * @brief Pure document identifier generator over an injected prefix and clock (the core of generateDocId()).
 *
 * The clock state starts at 0, as in a thread that has not generated yet.
 */
class DocIdGenerator
{
public:
    explicit DocIdGenerator(const std::array<uint8_t, DOC_ID_PREFIX_SIZE>& prefix) noexcept;

    /**
     * @brief Returns the identifier for the clock reading nowNs (nanoseconds since the epoch).
     */
    std::string next(int64_t nowNs);

private:
    std::array<uint8_t, DOC_ID_PREFIX_SIZE> m_prefix;
    int64_t m_last;
};
} // namespace detail

/**
 * @brief Maximum accepted length, in bytes, of a resource identifier.
 */
constexpr size_t MAX_RESOURCE_ID_LENGTH = 256;

/**
 * @brief Human readable description of the resource identifier rules, for error messages.
 */
constexpr std::string_view RESOURCE_ID_RULES =
    "it must be non-empty, at most 256 characters long and must not contain control characters";

/**
 * @brief Validates a resource identifier.
 *
 * Resource identifiers are opaque to the engine: any UUID version (v4, v5, ...) or any other
 * identifier format is accepted, as they are only used as keys and never interpreted. They are
 * compared byte by byte, so the engine never normalizes them (no case folding, no trimming).
 *
 * The only constraints protect the places where the identifier is echoed (logs, error messages,
 * API responses) and bound the size of the keys:
 *  - it must not be empty, since an empty value means "no identifier";
 *  - it must not exceed MAX_RESOURCE_ID_LENGTH bytes;
 *  - it must not contain control characters (0x00-0x1F, 0x7F).
 *
 * @param id The identifier string to validate
 * @return true if the string is a usable identifier, false otherwise
 */
inline bool isValidResourceId(const std::string& id)
{
    if (id.empty() || id.size() > MAX_RESOURCE_ID_LENGTH)
    {
        return false;
    }

    return std::none_of(id.begin(), id.end(), [](unsigned char c) { return c < 0x20 || c == 0x7F; });
}

/**
 * @brief Generates a random hexadecimal string of the specified length (thread-safe).
 *
 * @param length The length of the hexadecimal string to generate
 * @return std::string The generated random hexadecimal string
 */
inline std::string randomHexString(const size_t length)
{
    constexpr char hexDigits[] = "0123456789abcdef";

    thread_local std::random_device rd;
    thread_local std::mt19937 gen(rd());
    thread_local std::uniform_int_distribution<> hex_dist(0, 15);

    std::string out;
    out.reserve(length);

    for (size_t i = 0; i < length; ++i)
    {
        out.push_back(hexDigits[hex_dist(gen)]);
    }

    return out;
}

} // namespace base::utils::generators

#endif // _BASE_GENERATORS_HPP
