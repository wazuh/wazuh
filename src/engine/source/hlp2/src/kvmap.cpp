#include "fmt/format.h"
#include <algorithm>
#include <hlp/parsec.hpp>
#include <iomanip>
#include <iostream>
#include <json/json.hpp>
#include <optional>
#include <string>
#include <vector>

using Stop = std::optional<std::string>;
using Options = std::vector<std::string>;

namespace hlp
{

/**
 * A KV map is a sequence of pairs (key,value) which are separated by sep
 * Each pair is also separated by psep.
 *
 * A value can be quoted, and the q
 * @param stop
 * @return
 */
parsec::Parser<json::Json> getKVParser(Stop str, Options lst)
{
    if ( ! str.has_value()) {
        throw std::invalid_argument(fmt::format("KV parser needs a stop string"));
    }
    const char stop = str.value()[0];

    if (lst.size() != 4)
    {
        throw std::invalid_argument(
            fmt::format("KV parser needs the number of fields to parse"));
    }

    auto sep = lst[0];
    auto dlm = lst[1];

    return [stop, sep, dlm](std::string_view text, int index)
    {

        std::string_view kvSeparator = sep;
        std::string_view pairSeparator = dlm;
        const char scapeChar = '\\';
        const char endMapToken =stop;

        // Pointer after last found pair, nullptr if not found
        const char* lastFoundOk = text.data()+index;
        auto it = lastFoundOk;

        /* Json Key-value */
        json::Json output_doc;

        /* -----------------------------------------------
                        Helpers lambdas
         ----------------------------------------------- */

        /*
          Return the pointer to the first `quoteChar` not escaped by `scapeChar` and the
          quoted string If there is no end quoteChar, return a nullptr. WARNING: This function
          can access 1 bytes before the start of the `str`
        */
        const auto getQuoted =
            [&scapeChar](const char* c_str) -> std::pair<const char*, std::string_view>
        {
            const char quoteChar = c_str[0];
            const char* ptr = c_str + 1;
            std::pair<const char*, std::string_view> result = {nullptr, ""};

            while (ptr = strchrnul(ptr, quoteChar), *ptr != '\0')
            {
                // Is not posible that ptr-2 < str
                bool escaped = (*(ptr - 1) == scapeChar);
                escaped = escaped && (*(ptr - 2) != scapeChar);

                if (!escaped)
                {
                    result = {ptr, std::string_view(c_str + 1, ptr - c_str - 1)};
                    break;
                }
                ptr++;
            }
            return result;
        };

        /*
          Return the pointer to the first `kvSeparator` not escaped by `scapeChar`.
          If there is no kvSeparator, return NULL
        */
        const auto getSeparator = [&kvSeparator, &scapeChar](const char* c_str)
        {
            const char* ptr = c_str;
            while (ptr = strstr(ptr, kvSeparator.data()), ptr != nullptr)
            {
                bool escaped = false;
                // worst cases:
                //    [=\0], [\=\0],[\\=\0],
                if (ptr + 1 >= c_str)
                {
                    escaped = (*(ptr - 1) == scapeChar);
                    if (escaped && (ptr + 2 >= c_str))
                    {
                        escaped = (*(ptr - 2) != scapeChar);
                    }
                }
                if (!escaped)
                {
                    break;
                }
                ptr++;
            }

            return ptr;
        };

        /*
          Returns a pair with the pointer to the start value (After key value separator)
          and the string_view to the Key.
          Rerturns a nullptr if there is no key value separator
        */
        const auto getKey =
            [&kvSeparator, &pairSeparator, &scapeChar, &getQuoted, &getSeparator](
                const char* c_str)
        {
            std::string_view key {};
            const char* ptr = c_str;
            if (*ptr == '"' || *ptr == '\'')
            {
                auto [endQuote, quoted] = getQuoted(ptr);
                // The key is valid only if valid only is followed by kvSeparator
                if (endQuote != nullptr
                    && kvSeparator.compare(
                           1, kvSeparator.size(), endQuote, kvSeparator.size())
                           == 0)
                {
                    key = std::move(quoted);
                    ptr = endQuote + kvSeparator.size() + 1;
                }
            }
            else
            {
                ptr = getSeparator(ptr);

                if (ptr != nullptr)
                {
                    // The key is valid only if no there a pairSeparator in the middle
                    auto tmpKey = std::string_view(c_str, ptr - c_str);
                    if (tmpKey.find(pairSeparator) == std::string_view::npos)
                    {
                        key = std::move(tmpKey);
                        ptr += kvSeparator.size();
                    }
                    else
                    {
                        ptr = nullptr;
                    }
                }
            }
            return std::pair<const char*, std::string_view> {ptr, key};
        };

        /* -----------------------------------------------
                        Start parsing
         ----------------------------------------------- */
        bool isSearchComplete = false; // True if the search is complete successfully
        while (!isSearchComplete)
        {
            /* Get Key */
            auto [strParsePtr, key] = getKey(lastFoundOk);
            if (strParsePtr == nullptr || key.empty())
            {
                // Goback to the last valid pair
                if (lastFoundOk > it)
                {
                    isSearchComplete = true;
                    lastFoundOk = lastFoundOk - pairSeparator.size();
                }
                // Fail to get key
                break;
            }

            // Get value
            std::string_view value {};
            // Check if value is quoted
            if (*strParsePtr == '"' || *strParsePtr == '\'')
            {
                auto [endQuotePtr, quotedValue] = getQuoted(strParsePtr);
                if (endQuotePtr != nullptr)
                {
                    value = std::move(quotedValue);
                    // Point to the next char after the end quote
                    strParsePtr = endQuotePtr + 1;
                    // Check if the next string is a pairSeparator
                    if (pairSeparator.compare(
                            0, pairSeparator.size(), strParsePtr, pairSeparator.size())
                        == 0)
                    {
                        // Go to the next pair (next char after the pairSeparator)
                        strParsePtr += pairSeparator.size();
                    }
                    else
                    {
                        // If there is no pairSeparator, the search is finished
                        isSearchComplete = true;
                    }
                }
                else
                {
                    // Fail to get value
                    break;
                }
            }
            else
            {
                // Search for pairSeparator
                auto endValuePtr = strstr(strParsePtr, pairSeparator.data());
                if (endValuePtr != nullptr)
                {
                    value = std::string_view(strParsePtr, endValuePtr - strParsePtr);
                    // if there a endMapToken before the pairSeparator, the search is finished
                    auto splitValue = value.find(endMapToken);
                    if (splitValue != std::string_view::npos)
                    {
                        value = value.substr(0, splitValue);
                        // Point to the endMapToken
                        strParsePtr = strParsePtr + splitValue;
                        isSearchComplete = true;
                    }
                    else
                    {
                        // Point to the next char after the pairSeparator
                        strParsePtr = endValuePtr + pairSeparator.size();
                    }
                }
                // No pairSeparator, search for endMapToken
                else if (endValuePtr = strchr(strParsePtr, endMapToken),
                         endValuePtr != nullptr)
                {
                    value = std::string_view(strParsePtr, endValuePtr - strParsePtr);
                    strParsePtr = endValuePtr;
                    isSearchComplete = true;
                    // Point to the next char after the endMapToken
                    // No fail but search is complete ok
                }
                else
                {
                    // No endMapToken, no pairSeparator, no end quoteChar
                    break;
                }
            }
            // Print key and value and iterator
            lastFoundOk = strParsePtr;

            // Check the value type and cast it
            output_doc.setString(value, fmt::format("/{}", key));
            // addValueToJson(output_doc, key, value);
        }

        // Validate if the map is valid with the endMapToken
        if (isSearchComplete)
        {
            // Invalid endMapToken
            if (endMapToken != *lastFoundOk)
            {
                lastFoundOk = nullptr;
            }
        }
        else
        {
            lastFoundOk = nullptr; // Fail to parse the map
        }

        if (lastFoundOk)
        {
            it = lastFoundOk;
        }


        if (nullptr != lastFoundOk) {
            return parsec::makeSuccess<json::Json>(output_doc, text, index);
        }
        return parsec::makeError<json::Json>("unable to parse KVmap", text, index);
    };
}

} // hlp namespace