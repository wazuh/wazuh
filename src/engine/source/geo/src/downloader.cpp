#include "downloader.hpp"

#include <algorithm>
#include <archiveHelper.hpp>
#include <filesystem>
#include <fstream>

#include <fmt/format.h>

#include <HTTPRequest.hpp>
#include <base/json.hpp>

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

base::OptError Downloader::extractMmdbFromTarGz(const std::string& tarGzContent, const std::string& outputPath) const
{
    // Get parent directory
    auto parentDir = std::filesystem::path(outputPath).parent_path();

    try
    {
        // Create temporary extraction directory at the same level as outputPath, not inside it
        const auto tmpExtractDir = parentDir / "tmp_extract";
        std::filesystem::create_directories(tmpExtractDir);

        // Extract only .mmdb files
        std::vector<std::string> extractOnly {".mmdb"};
        const std::atomic<bool> forceStop = false;

        Utils::ArchiveHelper::decompressTarGz(tarGzContent, tmpExtractDir.string(), extractOnly, forceStop);

        // Find the extracted .mmdb file and move it to the final path
        bool found = false;
        for (const auto& entry : std::filesystem::recursive_directory_iterator(tmpExtractDir))
        {
            if (entry.is_regular_file() && entry.path().extension() == ".mmdb")
            {
                std::filesystem::rename(entry.path(), outputPath);
                found = true;
                break;
            }
        }

        // Clean up temporary directory
        std::filesystem::remove_all(tmpExtractDir);

        if (!found)
        {
            return base::Error {"No .mmdb file found in tar.gz archive"};
        }

        return base::noError();
    }
    catch (const std::exception& e)
    {
        return base::Error {fmt::format("Failed to extract tar.gz archive: {}", e.what())};
    }
}
} // namespace geo
