#ifndef _GEO_DOWNLOADER_HPP
#define _GEO_DOWNLOADER_HPP

#include <geo/idownloader.hpp>

namespace geo
{
class Downloader : public IDownloader
{
    long m_timeout; ///< Maximum time in milliseconds for HTTP requests (0 = no timeout).

public:
    explicit Downloader(long timeout = 0)
        : m_timeout(timeout)
    {
    }
    virtual ~Downloader() = default;

    base::RespOrError<std::string> downloadHTTPS(const std::string& url) const override;
    base::RespOrError<json::Json> downloadManifest(const std::string& url) const override;
    base::OptError extractMmdbFromGz(const std::string& tarGzContent, const std::string& outputPath) const override;
};
} // namespace geo

#endif // _GEO_DOWNLOADER_HPP
