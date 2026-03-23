#ifndef _BASE_SANITIZERS_HPP
#define _BASE_SANITIZERS_HPP

#include <cctype>
#include <string>
#include <string_view>

/**
 * @brief Namespace for string sanitization utilities.
 */
namespace sanitizer
{

/**
 * @brief Normalize a string by lowercasing, replacing separators with underscores,
 *        and discarding non-alphanumeric characters.
 *
 * Rules:
 * - ASCII uppercase letters are converted to lowercase.
 * - Alphanumeric characters and underscores are kept.
 * - Space, '/', '.', '-', '\\', ':' are replaced by '_' (consecutive separators collapse).
 * - Other characters are discarded.
 * - Trailing '_' is removed.
 *
 * @param in Input string view.
 * @param out Output string (cleared before writing).
 */
inline void basicNormalize(std::string_view in, std::string& out) noexcept
{
    out.clear();
    bool lastUnderscore = false;

    auto push_underscore = [&]() noexcept
    {
        if (!out.empty() && !lastUnderscore)
        {
            out.push_back('_');
            lastUnderscore = true;
        }
    };

    for (unsigned char c : in)
    {
        // a) ASCII lowercase letters
        if (c >= 'A' && c <= 'Z')
        {
            c = static_cast<unsigned char>(c + 32);
        }

        // b) alphanumeric or '_'
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '_')
        {
            if (c == '_')
            {
                push_underscore();
            }
            else
            {
                out.push_back(static_cast<char>(c));
                lastUnderscore = false;
            }
            continue;
        }

        // c) separators → '_'
        if (c == ' ' || c == '/' || c == '.' || c == '-' || c == '\\' || c == ':')
        {
            push_underscore();
        }
        // d) other chars: discard
    }

    // e) remove the final '_' if it remains
    if (!out.empty() && out.back() == '_')
    {
        out.pop_back();
    }
}

} // namespace sanitizer

#endif // _BASE_SANITIZERS_HPP
