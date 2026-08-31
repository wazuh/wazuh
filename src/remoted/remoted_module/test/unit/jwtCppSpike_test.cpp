/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * August 25, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// SPIKE (issue #38582, JWT agent authentication -- plan E0): pins the behaviours of the vendored
// jwt-cpp (0.7.2, nlohmann traits) that the `wazuh-agent+jwt` profile depends on. No product code
// is exercised: the suite only records what the library does with duplicate JSON members,
// base64url padding/alphabet/trailing bits, NumericDate types, claim enumeration, `leeway` and
// HS256 keys that contain 0x00, so the profile's Verifier knows exactly which checks it must own.
//
// The assertions record OBSERVED behaviour, not a feature contract: if a jwt-cpp bump changes any
// of them, this suite fails and the Verifier's assumptions must be revisited. Cases started as
// [hypothesis] and were corrected to the observed result when the first run disagreed.
//
// DISABLED_TraitsBenchmark is the traits microbenchmark behind decision J7 (run by hand with
// --gtest_also_run_disabled_tests, ideally from an -O2 build -- the UNIT_TEST tree is unoptimised).

#include <gtest/gtest.h>

#include <jwt-cpp/traits/nlohmann-json/traits.h>

#include <rapidjson/reader.h>
#include <rapidjson/stringbuffer.h>

#include <openssl/evp.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <set>
#include <string>
#include <system_error>
#include <vector>

namespace
{
    using Traits = jwt::traits::nlohmann_json;
    using Base64Url = jwt::alphabet::base64url;

    struct FixedClock
    {
        std::chrono::system_clock::time_point tp;
        std::chrono::system_clock::time_point now() const
        {
            return tp;
        }
    };

    constexpr std::int64_t kNow = 1'700'000'000;

    std::chrono::system_clock::time_point at(std::int64_t epoch)
    {
        return std::chrono::system_clock::time_point {std::chrono::seconds {epoch}};
    }

    // jwt::verify with a fixed clock; a helper (not an inline template call) so the expression can
    // live inside gtest macros, whose argument list would otherwise split at the template comma.
    jwt::verifier<FixedClock, Traits> verifierAt(std::int64_t now)
    {
        return jwt::verify<FixedClock, Traits>(FixedClock {at(now)});
    }

    // 32-byte key with an embedded 0x00 and a high byte, the shape a decoded 64-hex client.keys
    // secret can take (never ASCII).
    std::string testKey()
    {
        std::string key(32, '\0');
        for (std::size_t i = 0; i < key.size(); ++i)
        {
            key[i] = static_cast<char>(i * 7);
        }
        key[5] = '\0';
        key[31] = static_cast<char>(0xff);
        return key;
    }

    std::string b64url(const std::string& raw)
    {
        return jwt::base::trim<Base64Url>(jwt::base::encode<Base64Url>(raw));
    }

    // Hand-assembled compact JWS: lets a case feed arbitrary header/payload JSON text (duplicates,
    // odd number types) that the builder API would never emit.
    std::string rawToken(const std::string& headerJson, const std::string& payloadJson, const std::string& key)
    {
        const std::string signingInput = b64url(headerJson) + "." + b64url(payloadJson);
        std::error_code ec;
        const std::string sig = jwt::algorithm::hs256 {key}.sign(signingInput, ec);
        EXPECT_FALSE(ec) << ec.message();
        return signingInput + "." + b64url(sig);
    }

    std::string profileHeader()
    {
        return R"({"alg":"HS256","kid":"001","typ":"wazuh-agent+jwt"})";
    }

    std::string profilePayload(std::int64_t iat = kNow, std::int64_t exp = kNow + 60)
    {
        return R"({"exp":)" + std::to_string(exp) + R"(,"iat":)" + std::to_string(iat) +
               R"(,"iss":"wazuh-agent/001","jti":"AAAAAAAAAAAAAAAAAAAAAA","nbf":)" + std::to_string(iat) +
               R"(,"sub":"001"})";
    }

    std::vector<std::string> split(const std::string& token)
    {
        std::vector<std::string> out;
        std::size_t start = 0;
        for (;;)
        {
            const auto dot = token.find('.', start);
            out.push_back(token.substr(start, dot == std::string::npos ? std::string::npos : dot - start));
            if (dot == std::string::npos)
            {
                return out;
            }
            start = dot + 1;
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Strict single-level object sink shared by the two SAX engines of the benchmark: exact key
    // allowlist, duplicate rejection, per-field type (string vs non-negative integer), no nesting.
    // This is the shape of the pre-parse the profile Verifier needs regardless of the JSON engine.
    // ---------------------------------------------------------------------------------------------
    struct Field
    {
        const char* name;
        bool integer;
    };

    constexpr std::array<Field, 3> kHeaderFields {{{"alg", false}, {"kid", false}, {"typ", false}}};
    constexpr std::array<Field, 6> kPayloadFields {
        {{"exp", true}, {"iat", true}, {"iss", false}, {"jti", false}, {"nbf", true}, {"sub", false}}};

    class StrictObjectSink
    {
    public:
        StrictObjectSink(const Field* fields, std::size_t count)
            : m_fields(fields)
            , m_count(count)
        {
        }

        bool startObject()
        {
            return ++m_depth == 1;
        }
        bool endObject()
        {
            return m_depth-- == 1;
        }
        bool key(const char* name, std::size_t len)
        {
            m_current = -1;
            for (std::size_t i = 0; i < m_count; ++i)
            {
                if (std::strlen(m_fields[i].name) == len && std::memcmp(m_fields[i].name, name, len) == 0)
                {
                    m_current = static_cast<int>(i);
                    break;
                }
            }
            if (m_current < 0 || (m_seen & (1u << m_current)) != 0)
            {
                return false; // unknown or duplicate member
            }
            m_seen |= (1u << m_current);
            return true;
        }
        bool string(const char* value, std::size_t len)
        {
            if (m_current < 0 || m_fields[m_current].integer)
            {
                return false;
            }
            m_strings[m_current].assign(value, len);
            return true;
        }
        bool integer(std::int64_t value)
        {
            if (m_current < 0 || !m_fields[m_current].integer || value < 0)
            {
                return false;
            }
            m_integers[m_current] = value;
            return true;
        }
        bool other()
        {
            return false;
        }
        bool complete() const
        {
            return m_depth == 0 && m_seen == ((1u << m_count) - 1u);
        }
        const std::string& str(std::size_t i) const
        {
            return m_strings[i];
        }
        std::int64_t num(std::size_t i) const
        {
            return m_integers[i];
        }

    private:
        const Field* m_fields;
        std::size_t m_count;
        int m_depth {0};
        int m_current {-1};
        unsigned m_seen {0};
        std::array<std::string, 6> m_strings {};
        std::array<std::int64_t, 6> m_integers {};
    };

    // rapidjson SAX adapter.
    struct RapidHandler : rapidjson::BaseReaderHandler<rapidjson::UTF8<>, RapidHandler>
    {
        explicit RapidHandler(StrictObjectSink& s)
            : sink(s)
        {
        }
        StrictObjectSink& sink;
        bool Null()
        {
            return sink.other();
        }
        bool Bool(bool)
        {
            return sink.other();
        }
        bool Int(int v)
        {
            return sink.integer(v);
        }
        bool Uint(unsigned v)
        {
            return sink.integer(v);
        }
        bool Int64(std::int64_t v)
        {
            return sink.integer(v);
        }
        bool Uint64(std::uint64_t v)
        {
            return v <= static_cast<std::uint64_t>(INT64_MAX) && sink.integer(static_cast<std::int64_t>(v));
        }
        bool Double(double)
        {
            return sink.other();
        }
        bool RawNumber(const char*, rapidjson::SizeType, bool)
        {
            return sink.other();
        }
        bool String(const char* s, rapidjson::SizeType n, bool)
        {
            return sink.string(s, n);
        }
        bool StartObject()
        {
            return sink.startObject();
        }
        bool Key(const char* s, rapidjson::SizeType n, bool)
        {
            return sink.key(s, n);
        }
        bool EndObject(rapidjson::SizeType)
        {
            return sink.endObject();
        }
        bool StartArray()
        {
            return sink.other();
        }
        bool EndArray(rapidjson::SizeType)
        {
            return sink.other();
        }
    };

    bool parseRapid(const std::string& json, StrictObjectSink& sink)
    {
        RapidHandler handler {sink};
        rapidjson::Reader reader;
        rapidjson::StringStream stream {json.c_str()};
        return !reader.Parse<rapidjson::kParseValidateEncodingFlag>(stream, handler).IsError() && sink.complete();
    }

    // nlohmann SAX adapter (json::sax_parse with a hand-rolled SAX class).
    struct NlohmannSax
    {
        using json = nlohmann::json;
        explicit NlohmannSax(StrictObjectSink& s)
            : sink(s)
        {
        }
        StrictObjectSink& sink;
        bool null()
        {
            return sink.other();
        }
        bool boolean(bool)
        {
            return sink.other();
        }
        bool number_integer(json::number_integer_t v)
        {
            return sink.integer(v);
        }
        bool number_unsigned(json::number_unsigned_t v)
        {
            return v <= static_cast<json::number_unsigned_t>(INT64_MAX) && sink.integer(static_cast<std::int64_t>(v));
        }
        bool number_float(json::number_float_t, const json::string_t&)
        {
            return sink.other();
        }
        bool string(json::string_t& s)
        {
            return sink.string(s.data(), s.size());
        }
        bool binary(json::binary_t&)
        {
            return sink.other();
        }
        bool start_object(std::size_t)
        {
            return sink.startObject();
        }
        bool key(json::string_t& k)
        {
            return sink.key(k.data(), k.size());
        }
        bool end_object()
        {
            return sink.endObject();
        }
        bool start_array(std::size_t)
        {
            return sink.other();
        }
        bool end_array()
        {
            return sink.other();
        }
        bool parse_error(std::size_t, const std::string&, const nlohmann::detail::exception&)
        {
            return false;
        }
    };

    bool parseNlohmannSax(const std::string& json, StrictObjectSink& sink)
    {
        NlohmannSax sax {sink};
        return nlohmann::json::sax_parse(json, &sax) && sink.complete();
    }
} // namespace

// --- DuplicateJsonMembers ------------------------------------------------------------------------
// The profile requires rejecting duplicate members (RFC 8259 §4 "SHOULD be unique"; RFC 7515 §4
// makes it a MUST for the header). nlohmann's DOM parser keeps the LAST value silently, so
// jwt::decode<nlohmann_json> cannot reject them: the Verifier needs its own strict pre-parse.
TEST(JwtCppSpike, DuplicateJsonMembers)
{
    const auto key = testKey();
    const auto token = rawToken(R"({"alg":"none","typ":"wazuh-agent+jwt","alg":"HS256"})",
                                R"({"sub":"001","sub":"002","exp":1700000060})",
                                key);

    const auto decoded = jwt::decode<Traits>(token);
    EXPECT_EQ(decoded.get_algorithm(), "HS256"); // last wins, first ("none") is dropped silently
    EXPECT_EQ(decoded.get_subject(), "002");
    EXPECT_EQ(decoded.get_header_json().size(), 2u); // {alg, typ}: the duplicate collapsed

    // The strict SAX sinks used by the benchmark do reject the same inputs (both engines).
    StrictObjectSink rapid {kHeaderFields.data(), kHeaderFields.size()};
    EXPECT_FALSE(parseRapid(R"({"alg":"none","kid":"001","typ":"wazuh-agent+jwt","alg":"HS256"})", rapid));
    StrictObjectSink nloh {kHeaderFields.data(), kHeaderFields.size()};
    EXPECT_FALSE(parseNlohmannSax(R"({"alg":"none","kid":"001","typ":"wazuh-agent+jwt","alg":"HS256"})", nloh));
}

// --- Base64UrlPadding ----------------------------------------------------------------------------
// jwt::decode pads with the base64url "fill" (`%3d`, i.e. percent-encoded '=') and then decodes.
// Consequences the Verifier must know: a literal '=' is NOT in the alphabet (rejected), the
// standard '+' '/' alphabet is rejected, a percent-encoded `%3d` fill is accepted or rejected
// depending on how many fills are needed, and non-zero trailing bits are silently ignored -- so
// canonical-form enforcement (RFC 7515 §2 / RFC 8725 §3.12 "no padding", exact trailing bits) has
// to be our own check on the raw segments.
TEST(JwtCppSpike, Base64UrlPadding)
{
    const auto key = testKey();
    const auto token = rawToken(profileHeader(), profilePayload(), key);
    auto parts = split(token);
    ASSERT_EQ(parts.size(), 3u);
    // Pick a segment that does not end on a 4-char boundary so the fill logic is really exercised
    // (the 48-byte header encodes to exactly 64 chars; the payload does not).
    const std::size_t seg = (parts[0].size() % 4 != 0) ? 0 : 1;
    ASSERT_NE(parts[seg].size() % 4, 0u);

    const auto missing = 4 - (parts[seg].size() % 4);
    const std::string literalPad(missing, '=');
    const auto withSegment = [&](const std::string& replacement)
    {
        auto copy = parts;
        copy[seg] = replacement;
        return copy[0] + "." + copy[1] + "." + copy[2];
    };

    EXPECT_NO_THROW(jwt::decode<Traits>(token)); // canonical (unpadded) form

    // Literal '=' padding: rejected because '=' is outside the base64url alphabet.
    EXPECT_THROW(jwt::decode<Traits>(withSegment(parts[seg] + literalPad)), std::runtime_error);

    // Percent-encoded fill (`%3d`, the base64url "fill" jwt-cpp itself uses): the decode path pads
    // FIRST (by length % 4) and only then counts fills, so a 2-fill input ("YQ%3d%3d" -> "a") is
    // accepted while a 1-fill input ("YWI%3d" -> "ab") trips "too much fill". Not a canonical-form
    // check in either direction.
    EXPECT_EQ(jwt::base::decode<Base64Url>(jwt::base::pad<Base64Url>("YQ%3d%3d")), "a");
    EXPECT_THROW(jwt::base::decode<Base64Url>(jwt::base::pad<Base64Url>("YWI%3d")), std::runtime_error);

    // Standard alphabet ('+', '/') is rejected before any JSON parsing happens.
    try
    {
        jwt::decode<Traits>("+///." + parts[1] + "." + parts[2]);
        FAIL() << "'+' and '/' must be outside the base64url alphabet";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_NE(std::string(e.what()).find("not within alphabet"), std::string::npos) << e.what();
    }

    // Non-canonical trailing bits: "YQ" is the canonical encoding of "a" (0x61); "YR" carries a
    // non-zero low bit in the last sextet and decodes to the same byte instead of failing.
    EXPECT_EQ(jwt::base::decode<Base64Url>(jwt::base::pad<Base64Url>("YQ")), "a");
    EXPECT_EQ(jwt::base::decode<Base64Url>(jwt::base::pad<Base64Url>("YR")), "a");

    // Two different byte strings may thus verify as the same token text is NOT canonical; the
    // profile's grammar check (alphabet + length%4 != 1 + zero trailing bits) closes this.
}

// --- NumericDateTypes ----------------------------------------------------------------------------
// RFC 7519 NumericDate is a JSON number; the profile narrows it to a non-negative integer. jwt-cpp's
// builder emits integers (basic_claim(const date&) stores integer_type), but decoding accepts a
// float (rounded via std::llround) and only rejects strings -- the exact type check is ours.
TEST(JwtCppSpike, NumericDateTypes)
{
    const auto key = testKey();

    const auto built = jwt::create<jwt::default_clock, Traits>(jwt::default_clock {})
                           .set_type("wazuh-agent+jwt")
                           .set_issued_at(at(kNow))
                           .set_expires_at(at(kNow + 60))
                           .sign(jwt::algorithm::hs256 {key});
    const auto decodedBuilt = jwt::decode<Traits>(built);
    const auto payload = decodedBuilt.get_payload_json();
    ASSERT_TRUE(payload.at("iat").is_number_integer() || payload.at("iat").is_number_unsigned());
    EXPECT_FALSE(payload.at("iat").is_number_float());
    EXPECT_EQ(payload.at("iat").dump(), std::to_string(kNow)); // no decimal point on the wire

    const auto floatExp =
        jwt::decode<Traits>(rawToken(profileHeader(), R"({"exp":1700000060.4,"iat":1700000000})", key));
    EXPECT_EQ(floatExp.get_payload_claim("exp").get_type(), jwt::json::type::number); // float, not integer
    EXPECT_EQ(floatExp.get_expires_at(), at(kNow + 60));                              // ...yet accepted and rounded

    const auto stringExp =
        jwt::decode<Traits>(rawToken(profileHeader(), R"({"exp":"1700000060","iat":1700000000})", key));
    EXPECT_THROW(stringExp.get_expires_at(), std::bad_cast);

    // Verifier's time checks happen on the rounded value too: a float exp passes jwt::verify.
    EXPECT_NO_THROW(verifierAt(kNow + 30).allow_algorithm(jwt::algorithm::hs256 {key}).verify(floatExp));
}

// --- ExactClaimEnumeration -----------------------------------------------------------------------
// Closed allowlists need the full member set of header and payload; get_header_json() /
// get_payload_json() expose them as nlohmann object_t (std::map) so exact-set comparison is cheap.
TEST(JwtCppSpike, ExactClaimEnumeration)
{
    const auto key = testKey();
    const auto decoded = jwt::decode<Traits>(rawToken(profileHeader(), profilePayload(), key));

    std::set<std::string> header;
    for (const auto& kv : decoded.get_header_json())
    {
        header.insert(kv.first);
    }
    EXPECT_EQ(header, (std::set<std::string> {"alg", "kid", "typ"}));

    std::set<std::string> payload;
    for (const auto& kv : decoded.get_payload_json())
    {
        payload.insert(kv.first);
    }
    EXPECT_EQ(payload, (std::set<std::string> {"exp", "iat", "iss", "jti", "nbf", "sub"}));

    // An unexpected member (aud) is visible to the enumeration, so it can be rejected by exact-set
    // comparison; jwt-cpp itself never complains about extra members.
    const auto withAud = jwt::decode<Traits>(
        rawToken(profileHeader(), R"({"aud":"x","exp":1700000060,"iat":1700000000,"sub":"001"})", key));
    EXPECT_TRUE(withAud.has_audience());
    EXPECT_EQ(withAud.get_payload_json().size(), 4u);
}

// --- LeewaySemantics -----------------------------------------------------------------------------
// jwt::verify's time checks: exp fails iff now > exp + leeway; iat/nbf fail iff now < claim - leeway;
// a missing exp/iat/nbf is simply not checked; default leeway is 0. The profile's TimePolicy
// (nbf==iat, exp>iat, exp-iat<=lifetime, iat<=now+skew, now<=exp+skew, now-iat<=lifetime+skew) is
// richer, so the Verifier owns time validation and NEVER stacks jwt-cpp's leeway on top.
TEST(JwtCppSpike, LeewaySemantics)
{
    const auto key = testKey();
    const auto alg = jwt::algorithm::hs256 {key};
    const auto token = jwt::decode<Traits>(rawToken(profileHeader(), profilePayload(kNow, kNow + 60), key));

    // exp inclusive: now == exp passes; now == exp + 1 fails with leeway 0 and passes with leeway 1.
    EXPECT_NO_THROW(verifierAt(kNow + 60).allow_algorithm(alg).verify(token));
    EXPECT_THROW(verifierAt(kNow + 61).allow_algorithm(alg).verify(token), jwt::error::token_verification_exception);
    EXPECT_NO_THROW(verifierAt(kNow + 61).allow_algorithm(alg).leeway(1).verify(token));

    // iat/nbf in the future: now == iat - 1 fails with leeway 0, passes with leeway 1.
    EXPECT_THROW(verifierAt(kNow - 1).allow_algorithm(alg).verify(token), jwt::error::token_verification_exception);
    EXPECT_NO_THROW(verifierAt(kNow - 1).allow_algorithm(alg).leeway(1).verify(token));

    // The error code surfaced for every time failure is the same (token_expired), even for iat.
    std::error_code ec;
    verifierAt(kNow - 1).allow_algorithm(alg).verify(token, ec);
    EXPECT_EQ(ec, jwt::error::token_verification_error::token_expired);

    // No exp at all: jwt-cpp verifies fine at any time -- presence is our check.
    const auto noExp = jwt::decode<Traits>(rawToken(profileHeader(), R"({"sub":"001"})", key));
    EXPECT_NO_THROW(verifierAt(kNow + 100000).allow_algorithm(alg).verify(noExp));
}

// --- Hs256RoundTrip ------------------------------------------------------------------------------
// HS256 with a 32-byte key containing 0x00: the key is passed with its full length (std::string,
// not a C string), the signature matches an independent OpenSSL one-shot HMAC, and tampering,
// wrong key and alg=none are all rejected.
TEST(JwtCppSpike, Hs256RoundTrip)
{
    const auto key = testKey();
    ASSERT_EQ(key.size(), 32u);
    ASSERT_EQ(key[5], '\0');

    const auto token = jwt::create<jwt::default_clock, Traits>(jwt::default_clock {})
                           .set_type("wazuh-agent+jwt")
                           .set_key_id("001")
                           .set_issuer("wazuh-agent/001")
                           .set_subject("001")
                           .set_id("AAAAAAAAAAAAAAAAAAAAAA")
                           .set_issued_at(at(kNow))
                           .set_not_before(at(kNow))
                           .set_expires_at(at(kNow + 60))
                           .sign(jwt::algorithm::hs256 {key});

    const auto parts = split(token);
    ASSERT_EQ(parts.size(), 3u);

    // The builder serialises through nlohmann: compact, members sorted alphabetically -- exactly the
    // hand-written canonical text of profilePayload(). A Signer that serialises the 6 claims itself
    // (sorted, compact) is therefore byte-compatible with the builder's output.
    EXPECT_EQ(parts[1], b64url(profilePayload()));

    // Independent HMAC over the signing input with the full 32-byte key.
    unsigned char mac[EVP_MAX_MD_SIZE];
    std::size_t macLen = 0;
    const std::string signingInput = parts[0] + "." + parts[1];
    ASSERT_NE(EVP_Q_mac(nullptr,
                        "HMAC",
                        nullptr,
                        "SHA256",
                        nullptr,
                        reinterpret_cast<const unsigned char*>(key.data()),
                        key.size(),
                        reinterpret_cast<const unsigned char*>(signingInput.data()),
                        signingInput.size(),
                        mac,
                        sizeof(mac),
                        &macLen),
              nullptr);
    ASSERT_EQ(macLen, 32u);
    EXPECT_EQ(b64url(std::string(reinterpret_cast<const char*>(mac), macLen)), parts[2]);

    const auto decoded = jwt::decode<Traits>(token);
    const auto verifier = verifierAt(kNow + 10)
                              .allow_algorithm(jwt::algorithm::hs256 {key})
                              .with_type("wazuh-agent+jwt")
                              .with_issuer("wazuh-agent/001");
    EXPECT_NO_THROW(verifier.verify(decoded));
    EXPECT_EQ(decoded.get_key_id(), "001");
    EXPECT_EQ(decoded.get_id(), "AAAAAAAAAAAAAAAAAAAAAA");

    // Tampered payload (sub 001 -> 002) with the original signature.
    std::string tamperedPayload = profilePayload();
    tamperedPayload.replace(tamperedPayload.find("\"sub\":\"001\""), 11, "\"sub\":\"002\"");
    const auto tampered = jwt::decode<Traits>(parts[0] + "." + b64url(tamperedPayload) + "." + parts[2]);
    EXPECT_THROW(verifier.verify(tampered), jwt::error::signature_verification_exception);

    // Wrong key (one bit flipped).
    auto other = key;
    other[0] = static_cast<char>(other[0] ^ 0x01);
    EXPECT_THROW(verifierAt(kNow + 10).allow_algorithm(jwt::algorithm::hs256 {other}).verify(decoded),
                 jwt::error::signature_verification_exception);

    // alg=none with an empty signature: rejected as wrong_algorithm (only HS256 allowed).
    const auto none = jwt::decode<Traits>(b64url(R"({"alg":"none","typ":"wazuh-agent+jwt"})") + "." + parts[1] + ".");
    std::error_code ec;
    verifier.verify(none, ec);
    EXPECT_EQ(ec, jwt::error::token_verification_error::wrong_algorithm);

    // ASCII-key confusion: signing with the 64-hex TEXT of the key must not verify against the
    // decoded bytes (the profile keys on the decoded 32 bytes, never the hex string).
    static const char* kHex = "0123456789abcdef";
    std::string hexText;
    for (unsigned char c : key)
    {
        hexText += kHex[c >> 4];
        hexText += kHex[c & 0x0f];
    }
    ASSERT_EQ(hexText.size(), 64u);
    const auto asciiSigned = jwt::decode<Traits>(rawToken(profileHeader(), profilePayload(), hexText));
    EXPECT_THROW(verifier.verify(asciiSigned), jwt::error::signature_verification_exception);
}

// --- Traits microbenchmark (J7) ------------------------------------------------------------------
// Variants (02-diseno-perfil-jwt.md §3):
//   (a)  jwt::decode<nlohmann_json> + jwt::verify (library as-is; cannot reject duplicates/float)
//   (a') own strict pre-parse via nlohmann::json::sax_parse + hs256::verify on the signing input
//   (c)  own strict pre-parse via rapidjson SAX (Reader) + hs256::verify
//   (0)  hs256::verify + base64url decode only -- the floor every variant pays
// Run: remoted_module_utest --gtest_also_run_disabled_tests --gtest_filter='JwtCppSpike.DISABLED_*'
TEST(JwtCppSpike, DISABLED_TraitsBenchmark)
{
    const auto key = testKey();
    const jwt::algorithm::hs256 alg {key};
    const auto token = rawToken(profileHeader(), profilePayload(), key);
    const auto parts = split(token);
    std::cout << "token bytes: " << token.size() << "\n";

    const auto decodeSegment = [](const std::string& s)
    {
        return jwt::base::decode<Base64Url>(jwt::base::pad<Base64Url>(s));
    };

    const auto variantA = [&]()
    {
        const auto decoded = jwt::decode<Traits>(token);
        std::error_code ec;
        verifierAt(kNow + 10)
            .allow_algorithm(alg)
            .with_type("wazuh-agent+jwt")
            .with_issuer("wazuh-agent/001")
            .verify(decoded, ec);
        return !ec && decoded.get_subject() == "001";
    };

    const auto strictAndVerify = [&](bool (*parse)(const std::string&, StrictObjectSink&))
    {
        const auto dot1 = token.find('.');
        const auto dot2 = token.find('.', dot1 + 1);
        const std::string header = decodeSegment(token.substr(0, dot1));
        const std::string payload = decodeSegment(token.substr(dot1 + 1, dot2 - dot1 - 1));
        const std::string signature = decodeSegment(token.substr(dot2 + 1));
        StrictObjectSink h {kHeaderFields.data(), kHeaderFields.size()};
        StrictObjectSink p {kPayloadFields.data(), kPayloadFields.size()};
        if (!parse(header, h) || !parse(payload, p))
        {
            return false;
        }
        if (h.str(0) != "HS256" || h.str(2) != "wazuh-agent+jwt" || h.str(1) != p.str(5) ||
            p.str(2) != "wazuh-agent/" + p.str(5) || p.num(1) != p.num(4) || p.num(0) <= p.num(1))
        {
            return false;
        }
        std::error_code ec;
        alg.verify(token.substr(0, dot2), signature, ec);
        return !ec;
    };

    const auto variantAPrime = [&]()
    {
        return strictAndVerify(&parseNlohmannSax);
    };
    const auto variantC = [&]()
    {
        return strictAndVerify(&parseRapid);
    };
    const auto variantFloor = [&]()
    {
        const auto dot2 = token.rfind('.');
        const std::string signature = decodeSegment(token.substr(dot2 + 1));
        decodeSegment(parts[0]);
        decodeSegment(parts[1]);
        std::error_code ec;
        alg.verify(token.substr(0, dot2), signature, ec);
        return !ec;
    };

    const auto bench = [&](const char* name, const auto& fn)
    {
        constexpr int kWarmup = 5'000;
        constexpr int kIterations = 200'000;
        for (int i = 0; i < kWarmup; ++i)
        {
            ASSERT_TRUE(fn());
        }
        const auto t0 = std::chrono::steady_clock::now();
        for (int i = 0; i < kIterations; ++i)
        {
            if (!fn())
            {
                FAIL() << name;
            }
        }
        const auto t1 = std::chrono::steady_clock::now();
        const double nsPerOp = std::chrono::duration<double, std::nano>(t1 - t0).count() / kIterations;
        std::cout << name << ": " << static_cast<long>(nsPerOp) << " ns/op\n";
        RecordProperty(name, static_cast<long>(nsPerOp));
    };

    bench("a_nlohmann_traits_decode_verify", variantA);
    bench("a_prime_nlohmann_sax_strict_plus_hs256", variantAPrime);
    bench("c_rapidjson_sax_strict_plus_hs256", variantC);
    bench("floor_base64_plus_hs256_only", variantFloor);
}
