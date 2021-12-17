#ifndef DEF_UTILS_WRAPPER_LINUX_HPP
#define DEF_UTILS_WRAPPER_LINUX_HPP

#include <string>


class UtilsWrapper final
{
    public:
        static std::string exec(const std::string& cmd, const size_t bufferSize = 128);
        static bool existsRegular(const std::string& path);
};

#endif // DEF_UTILS_WRAPPER_LINUX_HPP
