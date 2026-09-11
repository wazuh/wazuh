/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * August 3, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_TEST_TLS_SERVER_HPP
#define _REMOTED_TEST_TLS_SERVER_HPP

// Shared fixtures for the tests that drive a REAL RestinioHttpServer over TLS: a throwaway
// certificate, a one-agent keystore, and a bearer-authenticated client that can read a response
// back (or deliberately walk away mid-response).
//
// Extracted from shutdownRace_test.cpp so the streaming tests in httpServer_test.cpp can use the
// same client rather than growing a second copy of the certificate/signing dance.

#include "auth/iAgentKeystore.hpp"
#include "jwt/canonicalAgentId.hpp"
#include "jwt/jwtRequestTokenSigner.hpp"
#include "jwt/secureBytes.hpp"

#include <asio/connect.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/read.hpp>
#include <asio/ssl.hpp>
#include <asio/write.hpp>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <optional>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

namespace remoted::test
{

    /// The single agent every TLS test authenticates as.
    constexpr remoted::auth::AgentId kTestAgentId {7};

    /// Its 32-byte HS256 key, as the FakeKeystore below reports it.
    inline std::vector<std::uint8_t> testAgentKey()
    {
        return std::vector<std::uint8_t>(32, 0x0B);
    }

    /// Keystore stub: one agent, numeric id 7.
    class FakeKeystore final : public remoted::auth::IAgentKeystore
    {
    public:
        // Registered as `any`: the known agent may connect from any address.
        std::optional<remoted::auth::AgentLookup> lookup(remoted::auth::AgentId agentId,
                                                         std::string_view) const override
        {
            if (agentId == kTestAgentId)
            {
                return remoted::auth::AgentLookup {testAgentKey(), true};
            }
            return std::nullopt;
        }
    };

    // Deliberately no destructor: this is returned by value, so a destructor that removed the files
    // would delete them out from under the copy the caller keeps. File cleanup is a separate,
    // never-returned RAII guard (ScratchFileCleanup) constructed in the test body.
    struct TestCertificate
    {
        std::string certPath;
        std::string keyPath;
    };

    /// @param prefix Distinguishes concurrent test binaries' scratch files.
    inline std::optional<TestCertificate> generateTestCertificate(const std::string& prefix)
    {
        const auto pid = std::to_string(::getpid());
        TestCertificate cert;
        cert.certPath = "/tmp/" + prefix + "_" + pid + ".crt";
        cert.keyPath = "/tmp/" + prefix + "_" + pid + ".key";
        const std::string cmd = "openssl req -x509 -newkey rsa:2048 -nodes -days 1 -keyout " + cert.keyPath + " -out " +
                                cert.certPath + " -subj /CN=localhost >/dev/null 2>&1";
        if (std::system(cmd.c_str()) != 0)
        {
            return std::nullopt;
        }
        return cert;
    }

    /// Removes a fixed set of scratch files on scope exit. Never copied/moved/returned.
    class ScratchFileCleanup final
    {
    public:
        explicit ScratchFileCleanup(std::vector<std::string> paths)
            : m_paths {std::move(paths)}
        {
        }
        ScratchFileCleanup(const ScratchFileCleanup&) = delete;
        ScratchFileCleanup& operator=(const ScratchFileCleanup&) = delete;
        ~ScratchFileCleanup()
        {
            for (const auto& path : m_paths)
            {
                std::remove(path.c_str());
            }
        }

    private:
        std::vector<std::string> m_paths;
    };

    /// Mints a fresh `wazuh-agent+jwt` bearer for @p agentId with @p key, exactly as an agent does
    /// (the shared JwtRequestTokenSigner; a new token -- new jti -- per call).
    inline std::string bearerToken(const std::vector<std::uint8_t>& key, remoted::auth::AgentId agentId = kTestAgentId)
    {
        const jwt_profile::v1::SecureBytes secret {key.data(), key.size()};
        const auto token = jwt_profile::v1::JwtRequestTokenSigner::sign(
            jwt_profile::v1::CanonicalAgentId::fromNumeric(agentId), secret, std::chrono::system_clock::now());
        return token ? *token : std::string {};
    }

    /// Builds the authenticated request bytes an agent would put on the wire: protocol-version 1
    /// and a bearer token for kTestAgentId. The token binds identity only -- not the target, not
    /// the body -- so the same helper serves every route.
    inline std::string
    signedRequest(const std::vector<std::uint8_t>& key, const std::string& target, const std::string& body)
    {
        std::string request = "POST " + target + " HTTP/1.1\r\n";
        request += "Host: 127.0.0.1\r\n";
        request += "protocol-version: 1\r\n";
        request += "Authorization: Bearer " + bearerToken(key) + "\r\n";
        request += "Content-Length: " + std::to_string(body.size()) + "\r\n";
        request += "Connection: close\r\n\r\n";
        request += body;
        return request;
    }

    /**
     * @brief Sends pre-built request bytes over a fresh TLS connection and reads the response.
     *
     * The raw building block under every send helper here; also used directly for
     * unauthenticated requests (e.g. the health probe, or the global-prefix 404 checks).
     *
     * @param readLimit 0 reads until the server closes (a whole response). A positive value stops
     *                  after roughly that many bytes and CLOSES the connection -- which is how a
     *                  test reproduces an agent walking away mid-transfer.
     * @return Whatever was read; empty when the connection could not be established.
     */
    inline std::string sendRawOverTls(std::uint16_t port, const std::string& requestBytes, std::size_t readLimit = 0)
    {
        std::string received;
        try
        {
            asio::io_context ioc;
            asio::ssl::context sslContext {asio::ssl::context::tls_client};
            sslContext.set_verify_mode(asio::ssl::verify_none);

            asio::ssl::stream<asio::ip::tcp::socket> stream {ioc, sslContext};
            asio::ip::tcp::resolver resolver {ioc};
            const auto endpoints = resolver.resolve("127.0.0.1", std::to_string(port));
            asio::connect(stream.next_layer(), endpoints);
            stream.handshake(asio::ssl::stream_base::client);

            asio::write(stream, asio::buffer(requestBytes));

            std::vector<char> buffer(64 * 1024);
            while (readLimit == 0 || received.size() < readLimit)
            {
                asio::error_code ec;
                const auto n = stream.read_some(asio::buffer(buffer), ec);
                if (ec)
                {
                    break; // EOF, or the server tore the connection down.
                }
                received.append(buffer.data(), n);
            }
            // Falling out of scope closes the socket -- abrupt when readLimit cut us short.
        }
        catch (const std::exception&)
        {
            // Best-effort: what matters is what the SERVER does, not a clean client teardown.
        }
        return received;
    }

    /// Sends an unauthenticated GET (no body, no Authorization) and returns the raw response.
    inline std::string sendGetRequest(std::uint16_t port, const std::string& target)
    {
        return sendRawOverTls(port, "GET " + target + " HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    }

    inline std::string sendSignedRequest(std::uint16_t port,
                                         const std::vector<std::uint8_t>& key,
                                         const std::string& target,
                                         const std::string& body,
                                         std::size_t readLimit = 0)
    {
        return sendRawOverTls(port, signedRequest(key, target, body), readLimit);
    }

    /// Sends a signed request and returns immediately, without reading any reply.
    inline void sendSignedRequestFireAndForget(std::uint16_t port,
                                               const std::vector<std::uint8_t>& key,
                                               const std::string& target,
                                               const std::string& body)
    {
        try
        {
            asio::io_context ioc;
            asio::ssl::context sslContext {asio::ssl::context::tls_client};
            sslContext.set_verify_mode(asio::ssl::verify_none);

            asio::ssl::stream<asio::ip::tcp::socket> stream {ioc, sslContext};
            asio::ip::tcp::resolver resolver {ioc};
            const auto endpoints = resolver.resolve("127.0.0.1", std::to_string(port));
            asio::connect(stream.next_layer(), endpoints);
            stream.handshake(asio::ssl::stream_base::client);
            asio::write(stream, asio::buffer(signedRequest(key, target, body)));
        }
        catch (const std::exception&)
        {
        }
    }

    /**
     * @brief Reads a response deliberately slowly: a trickle client.
     *
     * Each read is small and spaced by @p pause, which is what a real agent on a slow WAN link
     * looks like. Used to show that a chunked transfer's per-write timeout rearms per chunk and so
     * does not bound the total duration.
     *
     * @param maxWait Gives up after this long, so a hung server fails the test instead of hanging it.
     */
    inline std::string sendSignedRequestTrickle(std::uint16_t port,
                                                const std::vector<std::uint8_t>& key,
                                                const std::string& target,
                                                const std::string& body,
                                                std::size_t readChunk,
                                                std::chrono::milliseconds pause,
                                                std::chrono::milliseconds maxWait)
    {
        std::string received;
        try
        {
            asio::io_context ioc;
            asio::ssl::context sslContext {asio::ssl::context::tls_client};
            sslContext.set_verify_mode(asio::ssl::verify_none);

            asio::ssl::stream<asio::ip::tcp::socket> stream {ioc, sslContext};
            asio::ip::tcp::resolver resolver {ioc};
            const auto endpoints = resolver.resolve("127.0.0.1", std::to_string(port));
            asio::connect(stream.next_layer(), endpoints);
            stream.handshake(asio::ssl::stream_base::client);

            asio::write(stream, asio::buffer(signedRequest(key, target, body)));

            std::vector<char> buffer(readChunk);
            const auto deadline = std::chrono::steady_clock::now() + maxWait;
            while (std::chrono::steady_clock::now() < deadline)
            {
                asio::error_code ec;
                const auto n = stream.read_some(asio::buffer(buffer), ec);
                if (ec)
                {
                    break; // EOF (transfer finished) or the server cut us off.
                }
                received.append(buffer.data(), n);
                std::this_thread::sleep_for(pause);
            }
        }
        catch (const std::exception&)
        {
        }
        return received;
    }

    /// Splits a raw HTTP response into its head and body. Returns {head, body}.
    inline std::pair<std::string, std::string> splitResponse(const std::string& raw)
    {
        const auto separator = raw.find("\r\n\r\n");
        if (separator == std::string::npos)
        {
            return {raw, {}};
        }
        return {raw.substr(0, separator), raw.substr(separator + 4)};
    }

    /**
     * @brief Decodes a chunked body, also reporting the sizes seen.
     *
     * The sizes matter as much as the payload: they are what proves the configured chunk size
     * actually reached the pump, which a decoded-body comparison alone would hide.
     *
     * @param complete Set false when no terminating 0-length chunk was found -- i.e. a truncated
     *                 transfer, which is exactly what an aborted stream must look like.
     */
    inline std::string decodeChunked(const std::string& body, std::vector<std::size_t>& sizes, bool& complete)
    {
        std::string decoded;
        complete = false;
        std::size_t index = 0;

        while (index < body.size())
        {
            const auto lineEnd = body.find("\r\n", index);
            if (lineEnd == std::string::npos)
            {
                break; // Header cut mid-way: truncated.
            }

            std::size_t chunkSize = 0;
            try
            {
                chunkSize = static_cast<std::size_t>(std::stoul(body.substr(index, lineEnd - index), nullptr, 16));
            }
            catch (const std::exception&)
            {
                break;
            }

            if (chunkSize == 0)
            {
                complete = true;
                break;
            }

            const auto dataStart = lineEnd + 2;
            if (dataStart + chunkSize > body.size())
            {
                break; // Payload cut mid-chunk: truncated.
            }

            decoded.append(body, dataStart, chunkSize);
            sizes.push_back(chunkSize);
            index = dataStart + chunkSize + 2; // skip the chunk's trailing CRLF
        }

        return decoded;
    }

} // namespace remoted::test

#endif // _REMOTED_TEST_TLS_SERVER_HPP
