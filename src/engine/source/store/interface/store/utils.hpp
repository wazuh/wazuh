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

/**
 * @brief Retrieves data from the store.
 *
 * This function retrieves data from the provided store using the specified name.
 * Optionally, if 'original' is set to true, it returns the original data.
 *
 * @param storeRead The store to retrieve data from.
 * @param name The name of the data to retrieve.
 * @param original Flag to indicate whether to retrieve the original data.
 * @return A variant containing the retrieved JSON data or an error.
 */
inline std::variant<json::Json, base::Error>
get(std::shared_ptr<const store::IStoreReader> storeRead, const base::Name& name, bool original = false)
{
    std::variant<json::Json, base::Error> result;
    auto jsonObject = storeRead->readDoc(name);
    if (std::holds_alternative<base::Error>(jsonObject))
    {
        return base::Error {fmt::format("Engine utils: '{}' could not be obtained from the "
                                        "store: {}.",
                                        name.fullName(),
                                        std::get<base::Error>(jsonObject).message)};
    }

    auto json = std::get<json::Json>(jsonObject);

    if (original || !json.exists("/json"))
    {
        return json;
    }

    auto jsonValue = json.getJson("/json");
    if (!jsonValue.has_value())
    {
        return base::Error {"/json path not found in JSON."};
    }

    return std::move(jsonValue.value());
}

/**
 * @brief Adds new data to the store.
 *
 * This function adds new data to the provided store using the specified name,
 * content JSON, and original data.
 *
 * @param istore The store to add data to.
 * @param name The name to associate with the data.
 * @param format The format of original.
 * @param contentJson The content JSON to add.
 * @param original The original data string to add.
 * @return An optional containing an error if the addition fails.
 */
inline std::optional<base::Error> add(std::shared_ptr<store::IStore> istore,
                                      const base::Name& name,
                                      const store::NamespaceId& namespaceId,
                                      const std::string& format,
                                      const json::Json& contentJson,
                                      const std::string& original)
{
    std::optional<base::Error> result = std::nullopt;
    const auto wrappedContent = jsonGenerator(contentJson, original, format);
    result = istore->createDoc(name, namespaceId, wrappedContent);

    return result;
}

/**
 * @brief Updates existing data in the store.
 *
 * This function updates existing data in the provided store using the specified name,
 * content JSON, and original data.
 *
 * @param istore The store to update data in.
 * @param name The name of the data to update.
 * @param format The format of original.
 * @param contentJson The content JSON for the update.
 * @param original The original data string for the update.
 * @return An optional containing an error if the update fails.
 */
inline std::optional<base::Error> update(std::shared_ptr<store::IStore> istore,
                                         const base::Name& name,
                                         const std::string& format,
                                         const json::Json& contentJson,
                                         const std::string& original)
{
    std::optional<base::Error> result = std::nullopt;
    const auto wrappedContent = jsonGenerator(contentJson, original, format);
    istore->updateDoc(name, wrappedContent);

    return result;
}
} // namespace utils
} // namespace store
#endif // _STORE_UTILS_H
