#ifndef _CMSTORE_ICMSTORE_CATEGORIES
#define _CMSTORE_ICMSTORE_CATEGORIES

#include <algorithm>
#include <string_view>
#include <vector>
namespace cm::store::categories
{

/**
 * @brief Available Categories and their Indexes
 *
 * This map defines the available categories
 * in the CMStore system. Any integration or asset should belong to one of these categories.
 */
inline const std::vector<std::string_view> AVAILABLE_CATEGORIES = {
    "UNDEFINED_1", "Applications", "Cloud Services", "Network Activity", "Security", "System Activity", "UNDEFINED_2"};

/**
 * @brief Get all available categories and their indexes in the namespace
 * @return const std::vector<std::string_view>& Vector of Category
 */
static const std::vector<std::string_view>& getAvailableCategories()
{
    return AVAILABLE_CATEGORIES;
}

/**
 * @brief Check if a category exists
 * @param category Category name to check (key sensitive)
 * @return true if the category exists, false otherwise
 */
static bool exists(std::string_view category)
{
    return std::find(AVAILABLE_CATEGORIES.begin(), AVAILABLE_CATEGORIES.end(), category) != AVAILABLE_CATEGORIES.end();
}

} // namespace cm::store::categories

#endif // _CM_STORE_ICMSTORE_CATEGORIES_HPP
