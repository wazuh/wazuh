#ifndef _BASE_HASH_HPP
#define _BASE_HASH_HPP

#include <cstddef>
#include <random>
#include <string>
#include <string_view>
#include <memory>

#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

/**
 * @brief Namespace for hash utility functions.
 *
 */

namespace base::utils::hash
{

/**
 * @brief Computes the MD5 hash of a given string.
 *
 * @param str The input string view to be hashed
 * @return std::string The MD5 hash as a lowercase hexadecimal string (32 characters),
 *                     or an empty string if any MD5 operation fails
 *
 */
inline std::string md5(std::string_view str)
{
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!ctx)
    {
        return "";
    }

    if (EVP_DigestInit_ex(ctx.get(), EVP_md5(), nullptr) != 1)
    {
        return "";
    }

    if (EVP_DigestUpdate(ctx.get(), str.data(), str.size()) != 1)
    {
        return "";
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    if (EVP_DigestFinal_ex(ctx.get(), digest, &digest_len) != 1)
    {
        return "";
    }

    // Convert binary digest to hexadecimal string
    std::string result;
    result.reserve(digest_len * 2);

    for (unsigned int i = 0; i < digest_len; ++i)
    {
        char hex[3];
        snprintf(hex, sizeof(hex), "%02x", digest[i]);
        result += hex;
    }

    return result;
}

/**
 * @brief Computes the SHA1 hash of a given string.
 *
 * @param str The input string view to be hashed
 * @return std::string The SHA1 hash as a lowercase hexadecimal string (40 characters),
 *                     or an empty string if any SHA1 operation fails
 *
 */
inline std::string sha1(std::string_view str)
{
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!ctx)
    {
        return "";
    }

    if (EVP_DigestInit_ex(ctx.get(), EVP_sha1(), nullptr) != 1)
    {
        return "";
    }

    if (EVP_DigestUpdate(ctx.get(), str.data(), str.size()) != 1)
    {
        return "";
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    if (EVP_DigestFinal_ex(ctx.get(), digest, &digest_len) != 1)
    {
        return "";
    }

    // Convert binary digest to hexadecimal string
    std::string result;
    result.reserve(digest_len * 2);

    for (unsigned int i = 0; i < digest_len; ++i)
    {
        char hex[3];
        snprintf(hex, sizeof(hex), "%02x", digest[i]);
        result += hex;
    }

    return result;
}

/**
 * @brief Computes the SHA256 hash of a given string.
 *
 * @param str The input string view to be hashed
 * @return std::string The SHA256 hash as a lowercase hexadecimal string (64 characters),
 *                     or an empty string if any SHA256 operation fails
 *
 */
inline std::string sha256(std::string_view str)
{
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!ctx)
    {
        return "";
    }

    if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1)
    {
        return "";
    }

    if (EVP_DigestUpdate(ctx.get(), str.data(), str.size()) != 1)
    {
        return "";
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    if (EVP_DigestFinal_ex(ctx.get(), digest, &digest_len) != 1)
    {
        return "";
    }

    // Convert binary digest to hexadecimal string
    std::string result;
    result.reserve(digest_len * 2);

    for (unsigned int i = 0; i < digest_len; ++i)
    {
        char hex[3];
        snprintf(hex, sizeof(hex), "%02x", digest[i]);
        result += hex;
    }

    return result;
}

} // namespace base::utils::hash

#endif // _BASE_HASH_HPP
