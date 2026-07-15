#include "hash_helper.hpp"

#include <openssl/evp.h>

#include <cstdio>
#include <memory>

namespace wazuh::container_baseline {

namespace {

std::string ToHex(const unsigned char* digest, unsigned int len)
{
    static const char kHexChars[] = "0123456789abcdef";
    std::string out;
    out.resize(static_cast<size_t>(len) * 2);
    for (unsigned int i = 0; i < len; ++i) {
        out[2 * i]     = kHexChars[(digest[i] >> 4) & 0x0F];
        out[2 * i + 1] = kHexChars[digest[i] & 0x0F];
    }
    return out;
}

struct EvpCtxDeleter
{
    void operator()(EVP_MD_CTX* ctx) const noexcept
    {
        if (ctx) EVP_MD_CTX_free(ctx);
    }
};
using EvpCtxPtr = std::unique_ptr<EVP_MD_CTX, EvpCtxDeleter>;

} // namespace

bool HashFile(const std::string& path, size_t max_bytes, FileHashes& out)
{
    out.md5.clear();
    out.sha1.clear();
    out.sha256.clear();

    std::FILE* fp = std::fopen(path.c_str(), "rb");
    if (fp == nullptr) return false;

    EvpCtxPtr md5_ctx(EVP_MD_CTX_new());
    EvpCtxPtr sha1_ctx(EVP_MD_CTX_new());
    EvpCtxPtr sha256_ctx(EVP_MD_CTX_new());
    if (!md5_ctx || !sha1_ctx || !sha256_ctx) {
        std::fclose(fp);
        return false;
    }

    EVP_DigestInit_ex(md5_ctx.get(), EVP_md5(), nullptr);
    EVP_DigestInit_ex(sha1_ctx.get(), EVP_sha1(), nullptr);
    EVP_DigestInit_ex(sha256_ctx.get(), EVP_sha256(), nullptr);

    constexpr size_t kChunkSize = 65536;
    unsigned char    buf[kChunkSize];
    size_t           total_read = 0;
    size_t           n;

    while ((n = std::fread(buf, 1, sizeof(buf), fp)) > 0) {
        if (max_bytes != 0 && total_read + n > max_bytes) {
            n = max_bytes - total_read;
            if (n == 0) break;
        }
        EVP_DigestUpdate(md5_ctx.get(), buf, n);
        EVP_DigestUpdate(sha1_ctx.get(), buf, n);
        EVP_DigestUpdate(sha256_ctx.get(), buf, n);
        total_read += n;
        if (max_bytes != 0 && total_read >= max_bytes) break;
    }
    std::fclose(fp);

    unsigned char md5_digest[EVP_MAX_MD_SIZE];
    unsigned char sha1_digest[EVP_MAX_MD_SIZE];
    unsigned char sha256_digest[EVP_MAX_MD_SIZE];
    unsigned int  md5_len = 0, sha1_len = 0, sha256_len = 0;

    EVP_DigestFinal_ex(md5_ctx.get(), md5_digest, &md5_len);
    EVP_DigestFinal_ex(sha1_ctx.get(), sha1_digest, &sha1_len);
    EVP_DigestFinal_ex(sha256_ctx.get(), sha256_digest, &sha256_len);

    out.md5    = ToHex(md5_digest, md5_len);
    out.sha1   = ToHex(sha1_digest, sha1_len);
    out.sha256 = ToHex(sha256_digest, sha256_len);
    return true;
}

} // namespace wazuh::container_baseline
