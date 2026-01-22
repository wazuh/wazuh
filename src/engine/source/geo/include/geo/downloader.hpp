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
    base::RespOrError<json::Json> downloadManifest(const std::string& url) const override;
    base::OptError extractMmdbFromGz(const std::string& tarGzContent, const std::string& outputPath) const override;
};
} // namespace geo

#endif // _GEO_DOWNLOADER_HPP
