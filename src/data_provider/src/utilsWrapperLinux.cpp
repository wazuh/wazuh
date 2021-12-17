#include "utilsWrapperLinux.hpp"
#include "cmdHelper.h"
#include "filesystemHelper.h"

std::string UtilsWrapper::exec(const std::string& cmd, const size_t bufferSize)
{
    return Utils::exec(cmd, bufferSize);
}

bool UtilsWrapper::existsRegular(const std::string& path)
{
    return Utils::existsRegular(path);
}
