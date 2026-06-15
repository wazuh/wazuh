#ifndef _CMSTORE_ICMSTORE_CATEGORIES
#define _CMSTORE_ICMSTORE_CATEGORIES

#include <algorithm>
#include <array>
#include <string_view>
namespace cm::store::categories
{

/**
 * @brief Special category for unclassified events.
 *
 * Events are tagged with this category by the root decoder when no integration
 * decoder matches. Output routing and metrics behavior for these events depend
 * on the policy flag `index_unclassified_events`.
 */
inline constexpr std::string_view UNCLASSIFIED_CATEGORY = "unclassified";

/**
 * @brief Available Categories and their Indexes
 *
 * This map defines the available categories
 * in the CMStore system. Any integration or asset should belong to one of these categories.
 */
inline constexpr std::array<std::string_view, 8> AVAILABLE_CATEGORIES = {"access-management",
                                                                         "applications",
                                                                         "cloud-services",
                                                                         "network-activity",
                                                                         "other",
                                                                         "security",
                                                                         "system-activity",
                                                                         UNCLASSIFIED_CATEGORY};

/**
 * @brief Get all available categories and their indexes in the namespace
 * @return const std::vector<std::string_view>& Vector of Category
 */
constexpr const auto& getAvailableCategories()
{
    return AVAILABLE_CATEGORIES;
}

/**
 * @brief Check if a category exists
 * @param category Category name to check (key sensitive)
 * @return true if the category exists, false otherwise
 */
constexpr bool exists(std::string_view category)
{
    for (auto c : AVAILABLE_CATEGORIES)
    {
        if (c == category)
        {
            return true;
        }
    }
    return false;
}

} // namespace cm::store::categories

#endif // _CM_STORE_ICMSTORE_CATEGORIES_HPP
