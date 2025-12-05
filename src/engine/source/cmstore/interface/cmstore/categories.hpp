#ifndef _CMSTORE_ICMSTORE_CATEGORIES
#define _CMSTORE_ICMSTORE_CATEGORIES

#include <string_view>
#include <unordered_map>
namespace cm::store::categories
{

/**
 * @brief Available Categories and their Indexes
 *
 * This map defines the available categories and their corresponding indexes
 * in the CMStore system. Any integration or asset should belong to one of these categories.
 */
inline const std::unordered_map<std::string_view, std::string_view> AVAILABLE_CATEGORIES_AND_INDEXES = {
    {"UNDEFINED_1", "wazuh-events-v5-access-management"},
    {"Applications", "wazuh-events-v5-applications"},
    {"Cloud Services", "wazuh-events-v5-cloud-services"},
    {"Network Activity", "wazuh-events-v5-network-activity"},
    {"Security", "wazuh-events-v5-security"},
    {"System Activity", "wazuh-events-v5-system-activity"},
    {"UNDEFINED_2", "wazuh-events-v5-other"}};

/**
 * @brief Get all available categories and their indexes in the namespace
 * @return const std::vector<std::tuple<std::string_view, std::string_view>>& Vector of tuples with (Category, Index)
 */
static const std::unordered_map<std::string_view, std::string_view>& getMapping()
{
    return AVAILABLE_CATEGORIES_AND_INDEXES;
}

/**
 * @brief Check if a category exists
 * @param category Category name to check (key sensitive)
 * @return true if the category exists, false otherwise
 */
static bool exists(std::string_view category)
{
    return AVAILABLE_CATEGORIES_AND_INDEXES.find(category) != AVAILABLE_CATEGORIES_AND_INDEXES.end();
}

} // namespace cm::store::categories

#endif // _CM_STORE_ICMSTORE_CATEGORIES_HPP
