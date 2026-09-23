/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * September 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "certificateDescriptor.hpp"

#include "ca_bundle/ca_bundle.hpp"

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <ctime>
#include <memory>
#include <utility>

namespace remoted::http
{
    namespace
    {
        using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;

        std::string hexOf(const unsigned char* bytes, std::size_t length)
        {
            static constexpr char kHex[] = "0123456789abcdef";
            std::string hex;
            hex.reserve(length * 2);
            for (std::size_t index = 0; index < length; ++index)
            {
                hex.push_back(kHex[bytes[index] >> 4]);
                hex.push_back(kHex[bytes[index] & 0x0F]);
            }
            return hex;
        }

        /// RFC 2253, except that non-ASCII stays UTF-8 instead of becoming \XX escapes: the value is
        /// shown to an operator, never parsed back.
        std::string nameOf(const X509_NAME* name)
        {
            if (name == nullptr)
            {
                return {};
            }
            BioPtr bio {BIO_new(BIO_s_mem()), &BIO_free};
            if (!bio || X509_NAME_print_ex(bio.get(), name, 0, XN_FLAG_RFC2253 & ~ASN1_STRFLGS_ESC_MSB) < 0)
            {
                ERR_clear_error();
                return {};
            }
            char* data = nullptr;
            const long length = BIO_get_mem_data(bio.get(), &data);
            return (data != nullptr && length > 0) ? std::string {data, static_cast<std::size_t>(length)}
                                                   : std::string {};
        }

        std::optional<std::int64_t> epochOf(const ASN1_TIME* time)
        {
            if (time == nullptr)
            {
                return std::nullopt;
            }
            std::tm broken {};
            if (ASN1_TIME_to_tm(time, &broken) != 1)
            {
                ERR_clear_error();
                return std::nullopt;
            }
            return static_cast<std::int64_t>(::timegm(&broken));
        }

        std::string serialOf(const X509* certificate)
        {
            const ASN1_INTEGER* serial = X509_get0_serialNumber(certificate);
            if (serial == nullptr)
            {
                return {};
            }
            std::unique_ptr<BIGNUM, decltype(&BN_free)> number {ASN1_INTEGER_to_BN(serial, nullptr), &BN_free};
            char* hex = number ? BN_bn2hex(number.get()) : nullptr;
            if (hex == nullptr)
            {
                ERR_clear_error();
                return {};
            }
            std::string text {hex};
            OPENSSL_free(hex);
            std::transform(text.begin(),
                           text.end(),
                           text.begin(),
                           [](unsigned char character) { return static_cast<char>(std::tolower(character)); });
            // BN_bn2hex writes a negative value with a leading '-'; the sign stays ahead of the radix.
            return text.rfind('-', 0) == 0 ? "-0x" + text.substr(1) : "0x" + text;
        }

        /// An iPAddress SAN is 4 or 16 raw bytes; anything else is not an address this code understands.
        std::string addressOf(const ASN1_OCTET_STRING* address)
        {
            const unsigned char* octets = ASN1_STRING_get0_data(address);
            const int length = ASN1_STRING_length(address);
            char text[INET6_ADDRSTRLEN] {};
            if (octets != nullptr && length == 4 && ::inet_ntop(AF_INET, octets, text, sizeof(text)) != nullptr)
            {
                return text;
            }
            if (octets != nullptr && length == 16 && ::inet_ntop(AF_INET6, octets, text, sizeof(text)) != nullptr)
            {
                return text;
            }
            return {};
        }

        std::vector<std::string> subjectAltNamesOf(const X509* certificate)
        {
            using GeneralNamesPtr = std::unique_ptr<GENERAL_NAMES, decltype(&GENERAL_NAMES_free)>;
            // X509_get_ext_d2i takes a non-const X509*; it decodes an extension already parsed into the
            // certificate and does not modify it observably.
            GeneralNamesPtr names {static_cast<GENERAL_NAMES*>(X509_get_ext_d2i(
                                       const_cast<X509*>(certificate), NID_subject_alt_name, nullptr, nullptr)),
                                   &GENERAL_NAMES_free};
            std::vector<std::string> result;
            if (!names)
            {
                ERR_clear_error();
                return result;
            }

            const int count = sk_GENERAL_NAME_num(names.get());
            for (int index = 0; index < count; ++index)
            {
                const GENERAL_NAME* entry = sk_GENERAL_NAME_value(names.get(), index);
                if (entry == nullptr)
                {
                    continue;
                }
                if (entry->type == GEN_DNS)
                {
                    // Length-delimited, as leafHasUsableSan() reads it: an IA5String may carry an embedded NUL.
                    const int length = ASN1_STRING_length(entry->d.dNSName);
                    if (length > 0)
                    {
                        result.emplace_back(reinterpret_cast<const char*>(ASN1_STRING_get0_data(entry->d.dNSName)),
                                            static_cast<std::size_t>(length));
                    }
                }
                else if (entry->type == GEN_IPADD)
                {
                    auto address = addressOf(entry->d.iPAddress);
                    if (!address.empty())
                    {
                        result.push_back(std::move(address));
                    }
                }
            }
            return result;
        }

    } // namespace

    std::string sha256Hex(std::string_view bytes)
    {
        std::array<unsigned char, SHA256_DIGEST_LENGTH> digest {};
        SHA256(reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size(), digest.data());
        return hexOf(digest.data(), digest.size());
    }

    std::string rfc3339Utc(std::int64_t epochSeconds)
    {
        const std::time_t seconds = static_cast<std::time_t>(epochSeconds);
        std::tm broken {};
        if (::gmtime_r(&seconds, &broken) == nullptr)
        {
            return {};
        }
        char text[32] {};
        return std::strftime(text, sizeof(text), "%Y-%m-%dT%H:%M:%SZ", &broken) > 0 ? std::string {text}
                                                                                    : std::string {};
    }

    std::optional<CertificateDescriptor> describeCertificate(const X509* certificate)
    {
        if (certificate == nullptr)
        {
            return std::nullopt;
        }
        const auto notBefore = epochOf(X509_get0_notBefore(certificate));
        const auto notAfter = epochOf(X509_get0_notAfter(certificate));
        if (!notBefore.has_value() || !notAfter.has_value())
        {
            return std::nullopt;
        }

        CertificateDescriptor descriptor;
        descriptor.subject = nameOf(X509_get_subject_name(certificate));
        descriptor.issuer = nameOf(X509_get_issuer_name(certificate));
        descriptor.subjectAltNames = subjectAltNamesOf(certificate);
        descriptor.notBefore = *notBefore;
        descriptor.notAfter = *notAfter;
        descriptor.serial = serialOf(certificate);
        descriptor.fingerprint = ca_bundle::identityOf(certificate);
        return descriptor;
    }
} // namespace remoted::http
