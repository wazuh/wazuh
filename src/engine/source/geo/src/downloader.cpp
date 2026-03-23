#include "downloader.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>

#include <fmt/format.h>

#include <HTTPRequest.hpp>
#include <base/json.hpp>
#include <zlibHelper.hpp>
namespace
{
// This write callback function will be called by libcurl as soon as there is data received that needs to be saved.
// For most transfers, this callback gets called many times and each invoke delivers another chunk of data.
size_t writeCallback(void* contents, size_t size, size_t nmemb, std::string* userp)
{
    userp->append((char*)contents, size * nmemb);
    return size * nmemb;
}

bool isMD5Hash(const std::string& str)
{
    // Check if the string has 32 characters and consists of hexadecimal digits
    return str.size() == 32 && std::all_of(str.begin(), str.end(), ::isxdigit);
}
} // namespace

namespace geo
{
// Function to download content of the URL into a std::string in memory
base::RespOrError<std::string> Downloader::downloadHTTPS(const std::string& url) const
{
    base::RespOrError<std::string> readBuffer;

    HTTPRequest::instance().get(
        RequestParameters {.url = HttpURL(url)},
        PostRequestParameters {
            .onSuccess = [&readBuffer](const std::string& response) { readBuffer = response; },
            .onError =
                [&readBuffer, url](const std::string& error, const long statusCode, const std::string& responseBody)
            {
                readBuffer = base::Error {fmt::format(
                    "Failed to download file from '{}', error: {}, status code: {}.", url, error.c_str(), statusCode)};
            }});

    return readBuffer;
}

base::RespOrError<json::Json> Downloader::downloadManifest(const std::string& url) const
{
    auto response = downloadHTTPS(url);
    if (base::isError(response))
    {
        return base::getError(response);
    }

    auto content = base::getResponse(response);

    try
    {
        auto manifest = json::Json(content.c_str());
        return manifest;
    }
    catch (const std::exception& e)
    {
        return base::Error {fmt::format("Failed to parse manifest JSON: {}", e.what())};
    }
}

base::OptError Downloader::extractMmdbFromGz(const std::string& gzContent, const std::string& outputPath) const
{
    auto parentDir = std::filesystem::path(outputPath).parent_path();

    try
    {
        // Create parent directory if it doesn't exist
        std::filesystem::create_directories(parentDir);

        // Create temporary .gz file
        const auto tmpGzFile = parentDir / "tmp_download.mmdb.gz";

        // Write compressed content to temporary file
        std::ofstream outFile(tmpGzFile, std::ios::binary);
        if (!outFile)
        {
            return base::Error {fmt::format("Failed to create temporary file: {}", tmpGzFile.string())};
        }
        outFile.write(gzContent.data(), gzContent.size());
        outFile.close();

        // Decompress using zlibHelper
        Utils::ZlibHelper::gzipDecompress(tmpGzFile, outputPath);

        // Clean up temporary file
        std::filesystem::remove(tmpGzFile);

        return base::noError();
    }
    catch (const std::exception& e)
    {
        return base::Error {fmt::format("Failed to extract gz archive: {}", e.what())};
    }
}
} // namespace geo
