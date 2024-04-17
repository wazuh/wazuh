#ifndef _GEO_DOWNLOADER_HPP
#define _GEO_DOWNLOADER_HPP

#include "idownloader.hpp"

namespace geo
{
class Downloader : public IDownloader
{
public:
    Downloader() = default;
    virtual ~Downloader() = default;

    base::RespOrError<std::string> downloadHTTPS(const std::string& url) override;
    std::string computeMD5(const std::string& data) override;
};
} // namespace geo

#endif // _GEO_DOWNLOADER_HPP
