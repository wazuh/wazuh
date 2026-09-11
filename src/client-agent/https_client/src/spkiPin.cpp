/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * September 8, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "spkiPin.hpp"

#include "digest.hpp"
#include "jwt/base64Url.hpp"

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <array>
#include <climits>
#include <cstdio>
#include <memory>
#include <utility>

namespace
{
    using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;
    using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;

    // OPENSSL_free is a macro, so decltype(&OPENSSL_free) does not compile --
    // i2d_PUBKEY's output buffer needs a functor deleter instead.
    struct OpensslFree
    {
        void operator()(unsigned char* pointer) const noexcept
        {
            OPENSSL_free(pointer);
        }
    };
    using DerBufPtr = std::unique_ptr<unsigned char, OpensslFree>;

    // A functor rather than decltype(&std::fclose): the function-pointer form
    // (as digest.cpp uses) makes GCC emit -Wignored-attributes, and this
    // module builds with -Wall -Wextra.
    struct FileClose
    {
        void operator()(std::FILE* file) const noexcept
        {
            std::fclose(file);
        }
    };
    using FilePtr = std::unique_ptr<std::FILE, FileClose>;

    void setError(SpkiPinError* out, SpkiPinError value)
    {
        if (out != nullptr)
        {
            *out = value;
        }
    }

    /// PEM_read_bio_X509 returns null both for "there was no certificate here
    /// at all" and for "there was one and it is broken", which are different
    /// operational stories: the first is what an HTML error page or a manager
    /// predating /cacerts looks like, the second is a corrupt or truncated
    /// body. PEM_R_NO_START_LINE is what separates them.
    SpkiPinError classifyPemFailure()
    {
        return ERR_GET_REASON(ERR_peek_last_error()) == PEM_R_NO_START_LINE ? SpkiPinError::NoCertificate
               : SpkiPinError::BadCertificate;
    }

    /// The digest itself, over one parsed certificate.
    ///
    /// X509_get0_pubkey + i2d_PUBKEY, deliberately, rather than
    /// X509_get_X509_PUBKEY + i2d_X509_PUBKEY: `openssl x509 -pubkey |
    /// openssl pkey -pubin -outform der` -- the recipe every runbook and the
    /// manager-side mint will use -- is i2d_PUBKEY at both stages, so this
    /// route matches the reference pipeline by construction rather than by
    /// coincidence. (Neither API preserves the certificate's original bytes:
    /// X509_PUBKEY caches no encoding, so both re-encode.) The two agree for
    /// RSA and for named-curve and explicit-parameter EC alike, and
    /// spkiPin_test.cpp asserts that so an OpenSSL bump cannot change it
    /// silently. i2d_PUBKEY also fails closed on a key type we cannot parse,
    /// which is the more useful outcome: a pin we could never verify a
    /// handshake against is not worth computing.
    ///
    /// shared/src/x509_op.c's w_x509_spki_sha256() computes the same value for authd, and
    /// delegating to it would leave one definition of the pin instead of two. It cannot be
    /// called from here: that file needs shared.h for os_calloc/os_free, and this module links
    /// no libwazuh by design (see CMakeLists). Closing that gap means lifting the leaf
    /// functions into a file free of shared.h, which is a change to code the manager owns.
    std::optional<SpkiDigest> digestOf(X509* certificate, SpkiPinError* error)
    {
        EVP_PKEY* publicKey = X509_get0_pubkey(certificate); // Borrowed; must not be freed.

        if (publicKey == nullptr)
        {
            setError(error, SpkiPinError::UnsupportedKey);
            return std::nullopt;
        }

        unsigned char* raw = nullptr;
        const int length = i2d_PUBKEY(publicKey, &raw);
        const DerBufPtr owned {raw};

        if (length <= 0 || !owned)
        {
            setError(error, SpkiPinError::UnsupportedKey);
            return std::nullopt;
        }

        SpkiDigest digest {};
        unsigned int digestLength = 0;

        if (EVP_Digest(owned.get(), static_cast<size_t>(length), digest.data(), &digestLength, EVP_sha256(),
                       nullptr) != 1 ||
                digestLength != SPKI_PIN_BYTES)
        {
            setError(error, SpkiPinError::Internal); // LCOV_EXCL_LINE: EVP failures are not reproducible here.
            return std::nullopt;                     // LCOV_EXCL_LINE
        }

        setError(error, SpkiPinError::None);
        return digest;
    }

    /// A BIO over `pem`, or null when the text cannot be one. BIO_new_mem_buf
    /// takes an int, so an oversized view is refused before the cast rather
    /// than wrapping into a negative length.
    BioPtr memoryBio(std::string_view pem)
    {
        if (pem.empty() || pem.size() > static_cast<std::size_t>(INT_MAX))
        {
            return {nullptr, BIO_free};
        }

        return {BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), BIO_free};
    }
} // namespace

std::vector<SpkiDigest> spkiSha256AllFromPem(std::string_view pem, SpkiPinError* error)
{
    std::vector<SpkiDigest> digests;

    // Leave the thread's OpenSSL error queue exactly as it was found: a real
    // libcurl request runs immediately before this in the bootstrap flow, and
    // residue here surfaces as a baffling TLS failure in unrelated code.
    ERR_set_mark();

    try
    {
        const BioPtr bio = memoryBio(pem);

        if (!bio)
        {
            setError(error, SpkiPinError::NoCertificate);
            ERR_pop_to_mark();
            return {};
        }

        SpkiPinError last = SpkiPinError::None;

        while (true)
        {
            const X509Ptr certificate {PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr), X509_free};

            if (!certificate)
            {
                last = classifyPemFailure();
                break;
            }

            SpkiPinError perCertificate = SpkiPinError::None;
            auto digest = digestOf(certificate.get(), &perCertificate);

            if (!digest)
            {
                setError(error, perCertificate);
                ERR_pop_to_mark();
                return {};
            }

            digests.push_back(*digest);
        }

        if (digests.empty())
        {
            // Nothing parsed: either there was no PEM block at all, or the
            // first one was broken. classifyPemFailure() already told us which.
            setError(error, last);
            ERR_pop_to_mark();
            return {};
        }

        // A trailing unparseable block after at least one good certificate is
        // the ordinary end-of-input case (PEM_R_NO_START_LINE), not an error;
        // a genuinely corrupt one is worth reporting even though the
        // certificates before it are returned.
        setError(error, last == SpkiPinError::NoCertificate ? SpkiPinError::None : last);
    }
    catch (...) // LCOV_EXCL_START: no allocation here is large enough to fail reproducibly.
    {
        setError(error, SpkiPinError::Internal);
        ERR_pop_to_mark();
        return {};
    } // LCOV_EXCL_STOP

    ERR_pop_to_mark();
    return digests;
}

std::optional<SpkiDigest> spkiSha256FromPem(std::string_view pem, SpkiPinError* error)
{
    SpkiPinError which = SpkiPinError::None;
    const auto digests = spkiSha256AllFromPem(pem, &which);

    if (digests.empty())
    {
        setError(error, which);
        return std::nullopt;
    }

    // A bundle whose later blocks are corrupt still yields a usable first
    // certificate, and the first is all this entry point promises.
    setError(error, SpkiPinError::None);
    return digests.front();
}

std::optional<SpkiDigest> spkiSha256FromDer(const void* der, std::size_t length, SpkiPinError* error)
{
    if (der == nullptr || length == 0 || length > static_cast<std::size_t>(LONG_MAX))
    {
        setError(error, SpkiPinError::NoCertificate);
        return std::nullopt;
    }

    ERR_set_mark();

    const auto* cursor = static_cast<const unsigned char*>(der);
    const X509Ptr certificate {d2i_X509(nullptr, &cursor, static_cast<long>(length)), X509_free};

    if (!certificate)
    {
        setError(error, SpkiPinError::BadCertificate);
        ERR_pop_to_mark();
        return std::nullopt;
    }

    auto digest = digestOf(certificate.get(), error);
    ERR_pop_to_mark();
    return digest;
}

std::string spkiPinHex(const SpkiDigest& digest)
{
    return toHexLower(digest.data(), digest.size());
}

std::string spkiPinBase64Url(const SpkiDigest& digest)
{
    return jwt_profile::v1::base64UrlEncode(digest.data(), digest.size());
}

SpkiPinMatch spkiPinCompare(const SpkiDigest& digest, std::string_view pin)
{
    // Constant time by construction: the canonicality gate below looks only at
    // the (public) pin TEXT, and then a single CRYPTO_memcmp covers all 32
    // bytes with no early exit on a differing one. Do not "optimize" this into
    // a byte loop, and do not add a fast path on the first byte.
    if (!jwt_profile::v1::isCanonicalBase64UrlOf(pin, SPKI_PIN_BYTES))
    {
        return SpkiPinMatch::MalformedPin;
    }

    const auto decoded = jwt_profile::v1::base64UrlDecodeCanonical(pin);

    if (!decoded || decoded->size() != SPKI_PIN_BYTES)
    {
        return SpkiPinMatch::MalformedPin; // LCOV_EXCL_LINE: the gate above already covers this.
    }

    return CRYPTO_memcmp(digest.data(), decoded->data(), SPKI_PIN_BYTES) == 0 ? SpkiPinMatch::Match
           : SpkiPinMatch::Mismatch;
}

std::optional<std::string> spkiPinnedCertificatePem(std::string_view pem, std::string_view pin,
                                                    SpkiPinError* error)
{
    // Same error-queue discipline as spkiSha256AllFromPem(): a libcurl request runs immediately
    // before this in the bootstrap, and residue left here surfaces as an unrelated TLS failure.
    ERR_set_mark();

    try
    {
        const BioPtr bio = memoryBio(pem);

        if (!bio)
        {
            setError(error, SpkiPinError::NoCertificate);
            ERR_pop_to_mark();
            return std::nullopt;
        }

        bool parsedAny = false;
        SpkiPinError last = SpkiPinError::None;

        while (true)
        {
            const X509Ptr certificate {PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr), X509_free};

            if (!certificate)
            {
                last = classifyPemFailure();
                break;
            }

            parsedAny = true;

            SpkiPinError perCertificate = SpkiPinError::None;
            const auto digest = digestOf(certificate.get(), &perCertificate);

            if (!digest)
            {
                setError(error, perCertificate);
                ERR_pop_to_mark();
                return std::nullopt;
            }

            if (spkiPinCompare(*digest, pin) != SpkiPinMatch::Match)
            {
                continue;
            }

            // Written back out from the parsed certificate rather than copied out of the input:
            // what the caller installs is then exactly one certificate, carrying none of the
            // other blocks or surrounding text that shared the body it arrived in.
            // (shared/src/x509_op.c's w_x509_certificates_pem() does the same for the manager;
            // see digestOf() for why this module cannot call into that file.)
            const BioPtr out {BIO_new(BIO_s_mem()), BIO_free};

            if (!out || PEM_write_bio_X509(out.get(), certificate.get()) != 1)
            {
                setError(error, SpkiPinError::Internal); // LCOV_EXCL_LINE: allocation failure only.
                ERR_pop_to_mark();
                return std::nullopt;
            }

            char* data = nullptr;
            const long length = BIO_get_mem_data(out.get(), &data);

            if (length <= 0 || data == nullptr)
            {
                setError(error, SpkiPinError::Internal); // LCOV_EXCL_LINE: unreachable after a good write.
                ERR_pop_to_mark();
                return std::nullopt;
            }

            setError(error, SpkiPinError::None);
            ERR_pop_to_mark();
            return std::string(data, static_cast<std::size_t>(length));
        }

        // Nothing matched. A bundle that parsed is not a malformed input -- it simply is not the
        // manager the token names -- so only a body that yielded no certificate at all reports a
        // parse error here.
        setError(error, parsedAny ? SpkiPinError::None : last);
    }
    catch (...) // LCOV_EXCL_START: no allocation here is large enough to fail reproducibly.
    {
        setError(error, SpkiPinError::Internal);
        ERR_pop_to_mark();
        return std::nullopt;
    } // LCOV_EXCL_STOP

    ERR_pop_to_mark();
    return std::nullopt;
}
