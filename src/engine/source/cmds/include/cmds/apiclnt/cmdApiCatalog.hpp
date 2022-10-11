#ifndef _CMD_APICLNT_CATALOG_HPP
#define _CMD_APICLNT_CATALOG_HPP

#include <string>

namespace cmd::apiclnt
{
void catalog(const std::string& socketPath,
             const std::string& methodStr,
             const std::string& uriStr,
             const std::string& format,
             const std::string& content);
} // namespace cmd::apiclnt

#endif // _CMD_APICLNT_CATALOG_HPP
