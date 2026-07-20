#ifndef _GEO_DOWNLOADER_HPP
#define _GEO_DOWNLOADER_HPP

#include <atomic>

#include <geo/idownloader.hpp>

namespace geo
{
class Downloader : public IDownloader
{
    long m_timeout; ///< Maximum time in milliseconds for HTTP requests (0 = no timeout).
    std::shared_ptr<const std::atomic<bool>> m_shouldRun; ///< Optional flag to interrupt in-flight downloads.

public:
    explicit Downloader(long timeout = 0)
        : m_timeout(timeout)
    {
    }
    virtual ~Downloader() = default;

    /**
     * @brief Set a should-run flag to enable mid-transfer cancellation.
     * @param flag Shared atomic flag; when set to false, in-flight downloads will be cancelled.
     */
    void setShouldRun(std::shared_ptr<const std::atomic<bool>> flag) { m_shouldRun = std::move(flag); }

    base::RespOrError<std::string> downloadHTTPS(const std::string& url) const override;
    base::RespOrError<json::Json> downloadManifest(const std::string& url) const override;
    base::OptError extractMmdbFromGz(const std::string& tarGzContent, const std::string& outputPath) const override;
};
} // namespace geo

#endif // _GEO_DOWNLOADER_HPP
