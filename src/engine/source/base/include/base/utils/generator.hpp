#ifndef _BASE_GENERATORS_HPP
#define _BASE_GENERATORS_HPP

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
 * @brief Validates if a given string is a valid UUID version 4.
 *
 * @param uuid The UUID string to validate
 * @return true if the string is a valid UUID v4, false otherwise
 */
inline bool isValidUUIDv4(const std::string& uuid)
{
    if (uuid.length() != UUID_V4_LENGTH)
    {
        return false;
    }

    for (size_t i = 0; i < UUID_V4_LENGTH; ++i)
    {
        char c = uuid[i];
        switch (i)
        {
            case 8:
            case 13:
            case 18:
            case 23:
                if (c != '-')
                {
                    return false;
                }
                break;
            case 14:
                if (c != '4') // UUID version 4
                {
                    return false;
                }
                break;
            case 19:
                if (c != '8' && c != '9' && c != 'a' && c != 'b') // UUID variant
                {
                    return false;
                }
                break;
            default:
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
                {
                    return false;
                }
                break;
        }
    }

    return true;
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
