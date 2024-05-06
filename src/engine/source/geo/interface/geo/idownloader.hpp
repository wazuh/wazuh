#ifndef _GEO_IDOWNLOADER_HPP
#define _GEO_IDOWNLOADER_HPP

#include <string>

#include <base/error.hpp>

namespace geo
{
class IDownloader
{
public:
    virtual ~IDownloader() = default;

    virtual base::RespOrError<std::string> downloadHTTPS(const std::string& url) const = 0;
    virtual std::string computeMD5(const std::string& data) const = 0;
    virtual base::RespOrError<std::string> downloadMD5(const std::string& url) const = 0;
};
} // namespace geo

#endif // _GEO_IDOWNLOADER_HPP
