#ifndef _GEO_IDOWNLOADER_HPP
#define _GEO_IDOWNLOADER_HPP

#include <string>

#include <base/error.hpp>
#include <base/json.hpp>

namespace geo
{
class IDownloader
{
public:
    virtual ~IDownloader() = default;

    virtual base::RespOrError<std::string> downloadHTTPS(const std::string& url) const = 0;

    /**
     * @brief Download and parse a manifest JSON file.
     *
     * @param url URL to download the manifest from.
     * @return base::RespOrError<json::Json> The parsed JSON manifest or an error.
     */
    virtual base::RespOrError<json::Json> downloadManifest(const std::string& url) const = 0;

    /**
     * @brief Extract .mmdb file from a gz archive.
     *
     * @param gzContent The content of the gz file.
     * @param outputPath Path where to write the extracted .mmdb file.
     * @return base::OptError An error if extraction failed.
     */
    virtual base::OptError extractMmdbFromGz(const std::string& gzContent,
                                                const std::string& outputPath) const = 0;
};
} // namespace geo

#endif // _GEO_IDOWNLOADER_HPP
