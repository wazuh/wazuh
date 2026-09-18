/*
 * Wazuh CA bundle library
 * Copyright (C) 2015, Wazuh Inc.
 * September 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "ca_bundle/ca_bundle.hpp"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h> // X509_check_ca

#include <algorithm>
#include <array>
#include <charconv>
#include <utility>

namespace ca_bundle
{
    namespace
    {
        using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;

        // OPENSSL_free() is a function-like MACRO (it forwards __FILE__/__LINE__ to CRYPTO_free()),
        // so `&OPENSSL_free` does not name a function pointer -- this thin wrapper is what
        // std::unique_ptr's deleter binds to instead.
        void freeOpensslBuffer(unsigned char* buffer) noexcept
        {
            OPENSSL_free(buffer);
        }

        /// The publication block's fixed shape: a fence, the title, a fence, four fields, a fence.
        constexpr std::string_view kFence = "##";
        constexpr std::string_view kTitle = "## Wazuh CA bundle";
        constexpr std::string_view kPublicationField = "## Publication:";
        constexpr std::string_view kContentField = "## Content-SHA256:";
        constexpr std::string_view kUpdatedField = "## Updated:";
        constexpr std::string_view kWrittenByField = "## Written by:";
        constexpr std::size_t kBlockLines = 8;

        /// Hex SHA-256 of the bytes, lowercase.
        std::string sha256Hex(std::string_view bytes)
        {
            std::array<unsigned char, SHA256_DIGEST_LENGTH> digest {};
            SHA256(reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size(), digest.data());

            static constexpr char kHex[] = "0123456789abcdef";
            std::string hex;
            hex.reserve(digest.size() * 2);
            for (const auto byte : digest)
            {
                hex.push_back(kHex[byte >> 4]);
                hex.push_back(kHex[byte & 0x0F]);
            }
            return hex;
        }

        /// The certificate's DER encoding, or nullopt when OpenSSL cannot produce it.
        std::optional<std::string> derOf(const X509* certificate)
        {
            if (certificate == nullptr)
            {
                return std::nullopt;
            }

            // i2d_X509 allocates when handed a null pointer-to-buffer, and takes a non-const X509*
            // because it may cache the encoding in it; it does not modify the certificate in any
            // observable way.
            unsigned char* raw = nullptr;
            const int length = i2d_X509(const_cast<X509*>(certificate), &raw);
            if (length <= 0 || raw == nullptr)
            {
                ERR_clear_error();
                OPENSSL_free(raw);
                return std::nullopt;
            }

            // RAII over the buffer i2d_X509 allocated: if the std::string construction below
            // throws std::bad_alloc, the buffer is still freed instead of leaking.
            const std::unique_ptr<unsigned char, decltype(&freeOpensslBuffer)> buffer {raw, &freeOpensslBuffer};
            return std::string {reinterpret_cast<const char*>(buffer.get()), static_cast<std::size_t>(length)};
        }

        /// Whether @p ca signed @p leaf: one signature check, the grain anyCaSignsLeaf() loops over.
        bool caSignsLeaf(const X509* ca, const X509* leaf)
        {
            if (ca == nullptr || leaf == nullptr)
            {
                return false;
            }

            EVP_PKEY* key = X509_get0_pubkey(ca);
            // X509_verify takes a non-const X509* (it may cache the encoding) but does not modify
            // the certificate in any observable way.
            return key != nullptr && X509_verify(const_cast<X509*>(leaf), key) == 1;
        }

        /// One-line form of a name, for logs and the tool's output. Empty when unavailable.
        std::string oneline(const X509_NAME* name)
        {
            if (name == nullptr)
            {
                return {};
            }
            // X509_NAME_oneline's fixed buffer is fine here: the value is for a log line, not for
            // matching, and a name longer than this is truncated rather than lost.
            char buffer[256];
            const char* text = X509_NAME_oneline(name, buffer, sizeof(buffer));
            return text != nullptr ? std::string {text} : std::string {};
        }

        /// An ASN.1 time as a UTC Unix timestamp, negative for a date before 1970; 0 only when it
        /// cannot be converted at all (ASN1_TIME_to_tm failed), never as a clamp on a real date.
        std::time_t asUnixTime(const ASN1_TIME* time)
        {
            if (time == nullptr)
            {
                return 0;
            }

            struct tm parts {};
            if (ASN1_TIME_to_tm(time, &parts) != 1)
            {
                ERR_clear_error();
                return 0;
            }

            // timegm() returned as-is: a certificate notBefore/notAfter before 1970 is a real date
            // (an operator's test fixture, a re-issued root backdated on purpose), not an error.
            return ::timegm(&parts);
        }

        /// @p line without its trailing whitespace (including the CR of a CRLF document).
        std::string_view withoutTrailingSpace(std::string_view line)
        {
            while (!line.empty() && (line.back() == '\r' || line.back() == ' ' || line.back() == '\t'))
            {
                line.remove_suffix(1);
            }
            return line;
        }

        /// The document's lines, trailing whitespace already off. A last line without '\n' counts.
        std::vector<std::string_view> linesOf(std::string_view text)
        {
            std::vector<std::string_view> lines;
            while (!text.empty())
            {
                const auto end = text.find('\n');
                if (end == std::string_view::npos)
                {
                    lines.push_back(withoutTrailingSpace(text));
                    break;
                }
                lines.push_back(withoutTrailingSpace(text.substr(0, end)));
                text.remove_prefix(end + 1);
            }
            return lines;
        }

        /// The value of `<prefix> <value>`, or nullopt when @p line is not that field.
        std::optional<std::string_view> fieldValue(std::string_view line, std::string_view prefix)
        {
            if (line.size() < prefix.size() || line.compare(0, prefix.size(), prefix) != 0)
            {
                return std::nullopt;
            }

            auto value = line.substr(prefix.size());
            while (!value.empty() && (value.front() == ' ' || value.front() == '\t'))
            {
                value.remove_prefix(1);
            }
            return value;
        }

        /// @p text as a non-negative decimal integer, or nullopt unless ALL of it converts.
        ///
        /// std::from_chars, not strtoll: the field comes from a std::string_view that may hold an
        /// embedded NUL (a document built with one), and strtoll's C-string reading stops at the
        /// first one, silently accepting whatever garbage follows as "the rest of the string" --
        /// exactly the bug this guards against. std::from_chars stops at the first non-digit
        /// (embedded NUL included) and hands back where it stopped, so trailing bytes of ANY kind
        /// -- a letter, an embedded NUL, more digits after one -- fail the `ptr == end` check
        /// below. A negative value is also refused: a publication timestamp is never one.
        std::optional<std::int64_t> asInt64(std::string_view text)
        {
            if (text.empty())
            {
                return std::nullopt;
            }

            std::int64_t value = 0;
            const char* const begin = text.data();
            const char* const end = text.data() + text.size();
            const auto result = std::from_chars(begin, end, value, 10);
            if (result.ec != std::errc {} || result.ptr != end || value < 0)
            {
                return std::nullopt;
            }
            return value;
        }

        /**
         * @brief The publication block starting at @p index, if a complete one starts there.
         *
         * All eight lines have to be in place and the publication has to be a number: half a block,
         * or one whose stamp cannot be read, is not a stamp, and the document reads as unpublished
         * rather than as broken. A hash that does not describe the certificates IS a block --
         * vouch() is what refuses it, as hash_mismatch.
         */
        std::optional<PublicationBlock> blockAt(const std::vector<std::string_view>& lines, std::size_t index)
        {
            if (index >= lines.size() || lines.size() - index < kBlockLines)
            {
                return std::nullopt;
            }
            if (lines[index] != kFence || lines[index + 1] != kTitle || lines[index + 2] != kFence ||
                lines[index + 7] != kFence)
            {
                return std::nullopt;
            }

            const auto publication = fieldValue(lines[index + 3], kPublicationField);
            const auto content = fieldValue(lines[index + 4], kContentField);
            const auto updated = fieldValue(lines[index + 5], kUpdatedField);
            const auto writtenBy = fieldValue(lines[index + 6], kWrittenByField);
            if (!publication || !content || !updated || !writtenBy)
            {
                return std::nullopt;
            }

            const auto stamped = asInt64(*publication);
            if (!stamped)
            {
                return std::nullopt;
            }

            PublicationBlock block;
            block.publication = *stamped;
            block.contentSha256 = std::string {*content};
            block.updated = std::string {*updated};
            block.writtenBy = std::string {*writtenBy};
            return block;
        }

        /// The first complete publication block of the document, wherever it sits.
        std::optional<PublicationBlock> findBlock(std::string_view pem)
        {
            const auto lines = linesOf(pem);
            for (std::size_t index = 0; index < lines.size(); ++index)
            {
                if (lines[index] != kFence)
                {
                    continue;
                }
                if (auto block = blockAt(lines, index))
                {
                    return block;
                }
            }
            return std::nullopt;
        }
    } // namespace

    void X509Deleter::operator()(X509* certificate) const noexcept
    {
        X509_free(certificate);
    }

    ParsedBundle parseBundle(std::string_view pem)
    {
        ParsedBundle result;
        if (pem.empty())
        {
            // Nothing to misunderstand: an empty document is well formed and carries nothing.
            result.wellFormed = true;
            return result;
        }

        BioPtr bio {BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), &BIO_free};
        if (!bio)
        {
            ERR_clear_error();
            return result;
        }

        // PEM_read_bio_X509 skips blocks that are not a CERTIFICATE, so a combined key+cert file
        // or a bundle yields exactly its certificates. It fails at end of input with a "no start
        // line" error; any other reason means a block it could not decode.
        for (X509Ptr certificate {PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr)}; certificate;
             certificate.reset(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr)))
        {
            result.certificates.push_back(std::move(certificate));
        }

        // The only clean way out of the loop. Anything else (bad base64, a truncated block, a
        // header the decoder chokes on) means we do not understand the whole input, and a document
        // we do not fully understand is not one to publish from.
        result.wellFormed = ERR_GET_REASON(ERR_peek_last_error()) == PEM_R_NO_START_LINE;
        ERR_clear_error();

        if (!result.wellFormed)
        {
            result.certificates.clear();
            return result;
        }

        // The `##` lines are comments to every PEM reader, so the block can sit anywhere the tool
        // or an operator left it -- and only a document we understood whole gets read for one.
        result.block = findBlock(pem);

        return result;
    }

    std::string serializeCertificates(const std::vector<X509Ptr>& certificates)
    {
        BioPtr bio {BIO_new(BIO_s_mem()), &BIO_free};
        if (!bio)
        {
            ERR_clear_error();
            return {};
        }

        for (const auto& certificate : certificates)
        {
            if (PEM_write_bio_X509(bio.get(), certificate.get()) != 1)
            {
                ERR_clear_error();
                return {};
            }
        }

        char* data = nullptr;
        const long length = BIO_get_mem_data(bio.get(), &data);
        return (data != nullptr && length > 0) ? std::string {data, static_cast<std::size_t>(length)} : std::string {};
    }

    std::string contentSha256(const std::vector<X509Ptr>& certificates)
    {
        std::vector<std::string> encodings;
        encodings.reserve(certificates.size());
        for (const auto& certificate : certificates)
        {
            auto der = derOf(certificate.get());
            if (!der)
            {
                // One certificate we cannot encode makes the whole answer meaningless: an empty
                // hash matches no block, so the bundle is never vouched for on a half content.
                return {};
            }
            encodings.push_back(std::move(*der));
        }

        // Sorted by the DER bytes themselves: the hash names the SET of certificates, so neither
        // the order they were written in nor the PEM wrapping around them can change it.
        std::sort(encodings.begin(), encodings.end());

        std::string content;
        for (const auto& der : encodings)
        {
            content += der;
        }
        return sha256Hex(content);
    }

    std::string identityOf(const X509* certificate)
    {
        auto der = derOf(certificate);
        if (!der)
        {
            return {};
        }
        return "x509-sha256:" + sha256Hex(*der);
    }

    bool anyCaSignsLeaf(const X509* leaf, const std::vector<X509Ptr>& cas)
    {
        if (leaf == nullptr)
        {
            return false;
        }
        for (const auto& ca : cas)
        {
            if (caSignsLeaf(ca.get(), leaf))
            {
                return true;
            }
        }
        ERR_clear_error(); // a failed X509_verify queues a signature error
        return false;
    }

    Vouch vouch(const ParsedBundle& bundle, const X509* leaf, std::size_t serializedBytes)
    {
        // Fixed order, first failure wins -- the caller's logs and the tool's exit codes name the
        // cause, so which guard answers has to be the same everywhere.
        if (bundle.certificates.empty())
        {
            return {0, GuardFailure::no_certificates};
        }
        if (!bundle.block)
        {
            return {0, GuardFailure::no_block};
        }
        // An empty computed hash (i2d_X509 failed on one certificate -- a null X509Ptr among
        // them, say) never avails a block, even one whose own Content-SHA256 is also empty: two
        // empty strings comparing equal would let a bundle we could not even hash through.
        const auto computedHash = contentSha256(bundle.certificates);
        if (computedHash.empty() || bundle.block->contentSha256 != computedHash)
        {
            return {0, GuardFailure::hash_mismatch};
        }
        if (!anyCaSignsLeaf(leaf, bundle.certificates))
        {
            return {0, GuardFailure::no_ca_signs_leaf};
        }
        if (bundle.certificates.size() > kMaxCertificates)
        {
            return {0, GuardFailure::too_many_certificates};
        }
        if (serializedBytes > kMaxSerializedBytes)
        {
            return {0, GuardFailure::too_many_bytes};
        }
        return {bundle.block->publication, GuardFailure::none};
    }

    std::string renderBlock(const PublicationBlock& block)
    {
        std::string text;
        text += std::string {kFence} + "\n";
        text += std::string {kTitle} + "\n";
        text += std::string {kFence} + "\n";
        text += std::string {kPublicationField} + " " + std::to_string(block.publication) + "\n";
        text += std::string {kContentField} + " " + block.contentSha256 + "\n";
        text += std::string {kUpdatedField} + " " + block.updated + "\n";
        text += std::string {kWrittenByField} + " " + block.writtenBy + "\n";
        text += std::string {kFence} + "\n";
        return text;
    }

    CertificateFacts describe(const X509* certificate, const X509* leaf)
    {
        CertificateFacts facts;
        if (certificate == nullptr)
        {
            return facts;
        }

        facts.subject = oneline(X509_get_subject_name(certificate));
        facts.issuer = oneline(X509_get_issuer_name(certificate));
        facts.identity = identityOf(certificate);
        facts.notBefore = asUnixTime(X509_get0_notBefore(certificate));
        facts.notAfter = asUnixTime(X509_get0_notAfter(certificate));
        // X509_check_ca takes a non-const X509* (it caches the extension flags it decodes).
        facts.isCa = X509_check_ca(const_cast<X509*>(certificate)) > 0;
        facts.signsLeaf = caSignsLeaf(certificate, leaf);
        ERR_clear_error(); // a failed X509_verify queues a signature error
        return facts;
    }

} // namespace ca_bundle
