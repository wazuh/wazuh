#include "downloader.hpp"

#include <algorithm>
#include <iomanip>
#include <openssl/evp.h>
#include <sstream>

#include <fmt/format.h>

#include <HTTPRequest.hpp>

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
                [&readBuffer, url](const std::string& error, const long statusCode)
            {
                readBuffer = base::Error {fmt::format(
                    "Failed to download file from '{}', error: {}, status code: {}.", url, error.c_str(), statusCode)};
            }});

    return readBuffer;
}

// Function to compute the MD5 hash of input data
std::string Downloader::computeMD5(const std::string& data) const
{
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        // Handle error
        return "";
    }

    if (EVP_DigestInit_ex(ctx, EVP_md5(), nullptr) != 1)
    {
        // Handle error
        EVP_MD_CTX_free(ctx);
        return "";
    }

    if (EVP_DigestUpdate(ctx, data.c_str(), data.size()) != 1)
    {
        // Handle error
        EVP_MD_CTX_free(ctx);
        return "";
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;

    if (EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1)
    {
        // Handle error
        EVP_MD_CTX_free(ctx);
        return "";
    }

    EVP_MD_CTX_free(ctx);

    std::stringstream ss;
    for (unsigned int i = 0; i < digest_len; ++i)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
    }

    return ss.str();
}

base::RespOrError<std::string> Downloader::downloadMD5(const std::string& url) const
{
    auto response = downloadHTTPS(url);
    if (base::isError(response))
    {
        return base::getError(response);
    }

    auto hash = base::getResponse(response);

    // Remove trailing newline character
    if (!hash.empty() && hash[hash.size() - 1] == '\n')
    {
        hash.pop_back();
    }

    if (!isMD5Hash(hash))
    {
        return base::Error {fmt::format("Invalid MD5 hash: '{}'", hash)};
    }

    return hash;
}
} // namespace geo
