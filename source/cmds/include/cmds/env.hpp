#ifndef _CMD_APICLNT_ENV_HPP
#define _CMD_APICLNT_ENV_HPP

#include <string>

namespace cmd
{

void environment(const std::string& socketPath,
                 const std::string& action,
                 const std::string& target);
}

#endif // _CMD_APICLNT_ENV_HPP