#include "downloader.hpp"

#include <algorithm>
#include <curl/curl.h>
#include <iomanip>
#include <openssl/evp.h>
#include <sstream>

#include <fmt/format.h>

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
// TODO: Should use http-request library instead of libcurl
base::RespOrError<std::string> Downloader::downloadHTTPS(const std::string& url) const
{
    CURL* curl;
    CURLcode res;
    std::string readBuffer;

    curl_global_init(CURL_GLOBAL_DEFAULT);

    curl = curl_easy_init();
    if (curl)
    {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

        // Enable SSL certificate verification
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);

        // Set option to follow redirects
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

        // Specify the write callback function
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);

        // Set pointer to pass to our write function
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);

        // Perform the request, res will get the return code
        res = curl_easy_perform(curl);

        // Check for errors
        if (res != CURLE_OK)
        {
            return base::Error {
                fmt::format("Failed to download file from '{}', error: {}", url, curl_easy_strerror(res))};
        }

        // Always cleanup
        curl_easy_cleanup(curl);
    }

    curl_global_cleanup();
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
