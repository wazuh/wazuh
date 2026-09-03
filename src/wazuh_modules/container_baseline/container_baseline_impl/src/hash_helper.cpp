#include "hash_helper.hpp"

#include <openssl/evp.h>

#include <cstdio>
#include <memory>
#include <vector>

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

/// One requested digest: its context and where to put the result.
struct Digest
{
    EvpCtxPtr    ctx;
    std::string* out{nullptr};
};

EvpCtxPtr MakeCtx(const EVP_MD* md)
{
    EvpCtxPtr ctx{EVP_MD_CTX_new()};
    if (!ctx) return nullptr;
    if (EVP_DigestInit_ex(ctx.get(), md, nullptr) != 1) return nullptr;
    return ctx;
}

struct FileCloser
{
    void operator()(std::FILE* fp) const noexcept
    {
        if (fp) std::fclose(fp);
    }
};

} // namespace

bool HashFile(const std::string& path, FileHashes& out, const HashSelection& selection)
{
    out.md5.clear();
    out.sha1.clear();
    out.sha256.clear();

    if (!selection.any()) return false;

    std::unique_ptr<std::FILE, FileCloser> fp{std::fopen(path.c_str(), "rb")};
    if (!fp) return false;

    std::vector<Digest> digests;
    digests.reserve(3);

    const auto add = [&digests](bool wanted, const EVP_MD* md, std::string& sink) -> bool {
        if (!wanted) return true;
        auto ctx = MakeCtx(md);
        if (!ctx) return false;
        digests.push_back(Digest{std::move(ctx), &sink});
        return true;
    };

    if (!add(selection.md5, EVP_md5(), out.md5)) return false;
    if (!add(selection.sha1, EVP_sha1(), out.sha1)) return false;
    if (!add(selection.sha256, EVP_sha256(), out.sha256)) return false;
    if (digests.empty()) return false;

    constexpr size_t kChunkSize = 65536;
    unsigned char    buf[kChunkSize];
    size_t           n;

    while ((n = std::fread(buf, 1, sizeof(buf), fp.get())) > 0) {
        for (auto& digest : digests) {
            if (EVP_DigestUpdate(digest.ctx.get(), buf, n) != 1) return false;
        }
    }

    // A short read caused by an I/O error would otherwise produce a digest of a
    // truncated read and present it as the file's hash.
    if (std::ferror(fp.get()) != 0) return false;

    for (auto& digest : digests) {
        unsigned char value[EVP_MAX_MD_SIZE];
        unsigned int  len = 0;
        if (EVP_DigestFinal_ex(digest.ctx.get(), value, &len) != 1) return false;
        *digest.out = ToHex(value, len);
    }

    return true;
}

} // namespace wazuh::container_baseline
