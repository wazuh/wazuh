#ifndef _CMD_APICLNT_CONNECTION_HPP
#define _CMD_APICLNT_CONNECTION_HPP

#include <cstring>
#include <string>
#include <vector>

namespace cmd::apiclnt
{

std::string connection(const std::string& socketPath, const std::string& request);

} // namespace cmd::apiclnt

#endif // _CMD_APICLNT_CONNECTION_HPP
