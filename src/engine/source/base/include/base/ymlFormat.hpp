#ifndef _BASE_YMLFORMAT_HPP
#define _BASE_YMLFORMAT_HPP

#include <sstream>
#include <string>
#include <vector>

/**
 * @brief Namespace for YAML formatting utilities.
 */
namespace base::ymlfmt
{
/**
 * @brief Convert a vector of strings to a YAML list string.
 *
 * @param array The vector of strings.
 * @return std::string YAML-formatted list (e.g. "- item1\n- item2\n").
 */
inline std::string toYmlStr(const std::vector<std::string>& array)
{
    std::stringstream ss;
    for (auto& str : array)
    {
        ss << "- " << str << std::endl;
    }
    return ss.str();
}
} // namespace base::ymlfmt

#endif // _BASE_YMLFORMAT_HPP
