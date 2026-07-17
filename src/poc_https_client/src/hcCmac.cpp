/* AES-CMAC request signing — SPIKE #37738 PoC (C++17 core). See hcCmac.hpp. */

#include "hcCmac.hpp"

#include <openssl/evp.h>
#include <openssl/params.h>

#include <array>
#include <cstdio>
#include <memory>

namespace
{
    using MacPtr = std::unique_ptr<EVP_MAC, decltype(&EVP_MAC_free)>;
    using MacCtxPtr = std::unique_ptr<EVP_MAC_CTX, decltype(&EVP_MAC_CTX_free)>;

    int hexNibble(char c)
    {
        if (c >= '0' && c <= '9') { return c - '0'; }
        if (c >= 'a' && c <= 'f') { return c - 'a' + 10; }
        if (c >= 'A' && c <= 'F') { return c - 'A' + 10; }
        return -1;
    }

    std::optional<std::array<uint8_t, 16>> hexToKey(const std::string& hex)
    {
        std::array<uint8_t, 16> key {};
        if (hex.size() != key.size() * 2)
        {
            return std::nullopt;
        }
        for (size_t i = 0; i < key.size(); i++)
        {
            const int hi = hexNibble(hex[2 * i]);
            const int lo = hexNibble(hex[2 * i + 1]);
            if (hi < 0 || lo < 0)
            {
                return std::nullopt;
            }
            key[i] = static_cast<uint8_t>((hi << 4) | lo);
        }
        return key;
    }
} // namespace

std::optional<std::string> HcCmac::macHex(const std::string& keyHex,
                                          const uint8_t* msg, size_t msgLen)
{
    const auto key = hexToKey(keyHex);
    if (!key)
    {
        return std::nullopt;
    }

    const MacPtr mac {EVP_MAC_fetch(nullptr, "CMAC", nullptr), EVP_MAC_free};
    if (!mac)
    {
        return std::nullopt;
    }
    const MacCtxPtr ctx {EVP_MAC_CTX_new(mac.get()), EVP_MAC_CTX_free};
    if (!ctx)
    {
        return std::nullopt;
    }

    char cipher[] = "AES-128-CBC";
    const OSSL_PARAM params[] = {OSSL_PARAM_utf8_string("cipher", cipher, 0),
                                 OSSL_PARAM_END};

    std::array<uint8_t, 16> tag {};
    size_t tagLen = 0;
    if (EVP_MAC_init(ctx.get(), key->data(), key->size(), params) != 1 ||
        EVP_MAC_update(ctx.get(), msg, msgLen) != 1 ||
        EVP_MAC_final(ctx.get(), tag.data(), &tagLen, tag.size()) != 1 ||
        tagLen != tag.size())
    {
        return std::nullopt;
    }

    static const char* digits = "0123456789abcdef";
    std::string hex;
    hex.reserve(2 * tag.size());
    for (const auto b : tag)
    {
        hex.push_back(digits[b >> 4]);
        hex.push_back(digits[b & 0x0f]);
    }
    return hex;
}

std::vector<uint8_t> HcCmac::canonicalRequest(const std::string& method,
                                              const std::string& target,
                                              const std::string& agentId,
                                              long timestamp,
                                              const uint8_t* body, size_t bodyLen)
{
    const std::string head = "WAZUH-REQUEST\n1\n" + method + "\n" + target + "\n" +
                             agentId + "\n" + std::to_string(timestamp) + "\n";
    std::vector<uint8_t> buf;
    buf.reserve(head.size() + bodyLen);
    buf.insert(buf.end(), head.begin(), head.end());
    if (body != nullptr && bodyLen > 0)
    {
        buf.insert(buf.end(), body, body + bodyLen);
    }
    return buf;
}
