#ifndef _STORE_UTILS_H
#define _STORE_UTILS_H

#include <memory>
#include <optional>
#include <variant>

#include <base/error.hpp>
#include <base/json.hpp>
#include <base/name.hpp>
#include <store/istore.hpp>

/**
 * @brief Store functionallity.
 *
 */
namespace store
{
namespace utils
{
/**
 * @brief Generates a wrapped JSON object with content and original data.
 *
 * This function takes a JSON content and an original string, and wraps them
 * in a new JSON object for further processing.
 *
 * @param contentJson The JSON content to wrap.
 * @param original The original data string.
 * @param format The format of original.
 * @return A JSON object containing the wrapped content and original data.
 */
inline const json::Json
jsonGenerator(const json::Json& contentJson, const std::string& original, const std::string& format)
{
    // Wraps the content in both json and yml
    auto wrappedContent = json::Json {};
    wrappedContent.setObject();

    // Save the original json and yml
    wrappedContent.set("/json", contentJson);
    wrappedContent.setString(original, "/original");
    wrappedContent.setString(format, "/format");

    return wrappedContent;
}

} // namespace utils
} // namespace store
#endif // _STORE_UTILS_H
