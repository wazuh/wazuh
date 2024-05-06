#ifndef _GEO_DOWNLOADER_HPP
#define _GEO_DOWNLOADER_HPP

#include <geo/idownloader.hpp>

namespace geo
{
class Downloader : public IDownloader
{
public:
    Downloader() = default;
    virtual ~Downloader() = default;

    base::RespOrError<std::string> downloadHTTPS(const std::string& url) const override;
    std::string computeMD5(const std::string& data) const override;
    base::RespOrError<std::string> downloadMD5(const std::string& url) const override;
};
} // namespace geo

#endif // _GEO_DOWNLOADER_HPP
