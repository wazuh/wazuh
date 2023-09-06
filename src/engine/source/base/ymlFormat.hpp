#ifndef _BASE_YMLFORMAT_HPP
#define _BASE_YMLFORMAT_HPP

#include <sstream>
#include <string>
#include <vector>

namespace base::ymlfmt
{
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
