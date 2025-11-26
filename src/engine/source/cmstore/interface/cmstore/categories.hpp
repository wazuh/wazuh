#ifndef _CMSTORE_ICMSTORE_CATEGORIES
#define _CMSTORE_ICMSTORE_CATEGORIES

#include <filesystem>
#include <fstream>
#include <memory>
#include <string_view>
#include <unordered_map>

#include <base/json.hpp>
namespace cm::store::categories
{

///< Env var to define categories file path
constexpr auto ENV_CM_CATEGORIES_FILE = "WAZUH_CM_CATEGORIES_FILE";

inline std::unordered_map<std::string, std::string> indexByCategories;

/**
 * @brief Convert category name to index name
 * @param category Category name to convert
 * @return Converted index name following the rule "wazuh-events-v5-" + category.toLowerCase().replace(" ", "-")
 */
static std::string categoryToIndex(const std::string& category)
{
    std::string index = "wazuh-events-v5-";
    std::string lowerCategory = category;
    std::transform(lowerCategory.begin(),
                   lowerCategory.end(),
                   lowerCategory.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    std::replace(lowerCategory.begin(), lowerCategory.end(), ' ', '-');
    index += lowerCategory;
    return index;
}

/**
 * @brief Load the mapping from the categories file.
 * @throws std::runtime_error on IO or parse errors.
 */
static void loadMappingFromFile()
{
    auto categoriesFilePathEnv = std::getenv(ENV_CM_CATEGORIES_FILE);
    std::filesystem::path categoriesPath =
        categoriesFilePathEnv ? categoriesFilePathEnv : "/var/ossec/etc/categories.json";

    std::ifstream file(categoriesPath);
    if (!file.is_open())
    {
        throw std::runtime_error("Failed to open file: " + categoriesPath.string());
    }

    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    if (file.fail())
    {
        throw std::runtime_error("Failed to read content from file: " + categoriesPath.string());
    }

    auto categoriesJson = json::Json(content.c_str());

    if (!categoriesJson.isArray())
    {
        throw std::runtime_error("Categories file must contain a JSON array");
    }

    indexByCategories.clear();
    auto categories = categoriesJson.getArray().value();
    for (const auto& category : categories)
    {
        auto sCategory = category.getString().value();
        indexByCategories[sCategory] = categoryToIndex(sCategory);
    }
}

/**
 * @brief Get full mapping.
 */
static const std::unordered_map<std::string, std::string>& getMapping()
{
    return indexByCategories;
}

/**
 * @brief Check if a category exists.
 */
static bool exists(const std::string& category)
{
    return indexByCategories.find(category) != indexByCategories.end();
}

/**
 * @brief Check if an index exist.
 */
static bool isValidIndex(const std::string& index)
{
    for (const auto& [_, idx] : indexByCategories)
    {
        if (idx == index)
        {
            return true;
        }
    }
    return false;
}

} // namespace cm::store::categories

#endif // _CM_STORE_ICMSTORE_CATEGORIES_HPP
