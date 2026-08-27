#ifndef _BASE_GENERATORS_HPP
#define _BASE_GENERATORS_HPP

#include <algorithm>
#include <cstddef>
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
 * @brief Generates a random UUID version 4 (thread-safe).
 */
inline std::string generateUUIDv4()
{
    // Hexadecimal digits as a compile-time constant
    constexpr char hexDigits[] = "0123456789abcdef";

    thread_local std::random_device rd;
    thread_local std::mt19937 gen(rd());
    thread_local std::uniform_int_distribution<> hex_dist(0, 15);
    thread_local std::uniform_int_distribution<> variant_dist(8, 11); // UUID variant: 8, 9, a, or b

    std::string uuid;
    uuid.reserve(UUID_V4_LENGTH);

    for (size_t i = 0; i < UUID_V4_LENGTH; ++i)
    {
        switch (i)
        {
            case 8:
            case 13:
            case 18:
            case 23: uuid.push_back('-'); break;
            case 14:
                uuid.push_back('4'); // UUID version 4
                break;
            case 19:
                uuid.push_back(hexDigits[variant_dist(gen)]); // UUID variant
                break;
            default: uuid.push_back(hexDigits[hex_dist(gen)]); break;
        }
    }

    return uuid;
}

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
