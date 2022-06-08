#ifndef _SOCKINTERFACE_COMMON_H
#define _SOCKINTERFACE_COMMON_H

#include <map>
#include <string>

namespace base::utils::socketInterface {

// Return codes
enum class CommRetval
{
    SUCCESS,
    INVALID_SOCKET,
    SIZE_ZERO,
    SIZE_TOO_LONG,
    SOCKET_ERROR,
};

const std::map<CommRetval, const std::string> CommRetval2Str = {
    {CommRetval::INVALID_SOCKET, "INVALID_SOCKET"},
    {CommRetval::SIZE_TOO_LONG, "SIZE_TOO_LONG"},
    {CommRetval::SIZE_ZERO, "SIZE_ZERO"},
    {CommRetval::SOCKET_ERROR, "SOCKET_ERROR"},
    {CommRetval::SUCCESS, "SUCCESS"}};


}


#endif
