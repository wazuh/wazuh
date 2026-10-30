/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/*
 * The config download over the real curl path (#38514): ConfigFetcher on a real CurlPerformer, over
 * TLS, against the fork-based fake manager answering in each shape #40900's manager can send
 * (fakeDownloadReply.hpp). fetch() is checked directly, and every attempt's HttpResponse is recorded
 * on the way through, so a failed download is pinned to the curl error behind it, not inferred.
 */

#include "callbackDispatcher.hpp"
#include "configFetcher.hpp"
#include "curlHandle.hpp"
#include "curlPerformer.hpp"
#include "digest.hpp"
#include "fakeManager.hpp"
#include "jwtSigner.hpp"
#include "keyProvider.hpp"
#include "moduleConfig.hpp"
#include "spoolFile.hpp"
#include "sysSeams.hpp"
#include "wpkFetcher.hpp"

#include <curl/curl.h>
#include <gtest/gtest.h>

#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

namespace
{
    constexpr uint16_t DOWNLOAD_PORT = 24940; // Owns 24940-24948; see facadeE2e's port map.
    const std::string KEY_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    /// About 256 KiB of merged.mg-like text: two zstd blocks, so half a frame still decodes to something.
    std::string configBlob()
    {
        std::string blob = "#merged.mg\n<agent_config>\n";

        for (int line = 0; blob.size() < 256 * 1024; line++)
        {
            blob += "  <localfile><location>/var/log/app-" + std::to_string(line) + ".log</location></localfile>\n";
        }

        return blob + "</agent_config>\n";
    }

    /// FakeManager takes fourteen positional arguments before the one this suite cares about.
    FakeManager downloadManager(uint16_t port, const std::string& blob, DownloadReply reply)
    {
        return FakeManager {port, KEY_HEX, /*tls=*/true, 0, blob, 0, 0, {}, {}, 0, 0, {}, 0, {}, DownloadOptions {reply}};
    }

    ModuleConfig downloadConfig(uint16_t port)
    {
        hc_config_t config {};
        std::strncpy(config.server_host, "127.0.0.1", sizeof(config.server_host) - 1);
        config.server_port = port;
        std::strncpy(config.agent_id, "001", sizeof(config.agent_id) - 1);
        config.verify_mode = HC_VERIFY_NONE; // What is under test is the body, not the handshake.
        config.stateful_timeout_ms = 20000;  // The /download timeout class.
        config.backoff_base_ms = 1;          // A retry only has to happen, not wait.
        config.backoff_cap_ms = 5;
        return ModuleConfig::fromC(config);
    }

    /// The real performer, keeping every response it hands back.
    class RecordingPerformer final : public IHttpPerformer
    {
        public:
            explicit RecordingPerformer(IHttpPerformer& inner)
                : m_inner(inner)
            {
            }

            HttpResponse perform(const HttpRequestSpec& spec) override
            {
                m_responses.push_back(m_inner.perform(spec));
                return m_responses.back();
            }

            const std::vector<HttpResponse>& responses() const
            {
                return m_responses;
            }

        private:
            IHttpPerformer& m_inner;
            std::vector<HttpResponse> m_responses;
    };

    std::string readFile(const std::string& path)
    {
        std::ifstream file {path, std::ios::binary};
        return std::string {std::istreambuf_iterator<char> {file}, std::istreambuf_iterator<char> {}};
    }

    /// Files in `dir`; a directory that can't be read counts as one, so it never passes for empty.
    size_t filesIn(const std::string& dir)
    {
        DIR* handle = opendir(dir.c_str());

        if (handle == nullptr)
        {
            return 1;
        }

        size_t count = 0;

        while (const dirent* entry = readdir(handle))
        {
            count += std::strcmp(entry->d_name, ".") != 0 && std::strcmp(entry->d_name, "..") != 0;
        }

        closedir(handle);
        return count;
    }

    /// The Accept-Encoding the fake manager saw on its last /download ("<absent>" for none).
    std::string acceptEncodingSeenBy(uint16_t port)
    {
        httplib::Client peek {std::string {"https://127.0.0.1:"} + std::to_string(port)};
        peek.enable_server_certificate_verification(false);
        const auto result = peek.Get("/peek/download-accept-encoding");
        return result ? result->body : std::string {"<peek failed>"};
    }

    /// Both /download fetchers on the real curl path, the shared signer and a spool directory of
    /// their own, so a test can tell that a failed download left nothing behind.
    class Downloader final
    {
        public:
            explicit Downloader(uint16_t port)
                : m_config(downloadConfig(port))
                , m_spoolDir(::testing::TempDir() + "hc_download_" + std::to_string(::getpid()) + "_" + std::to_string(port))
                , m_signer("001", m_keyProvider)
                , m_curl(m_config, defaultCurlHandleFactory())
                , m_performer(m_curl)
                , m_spoolFactory(m_spoolDir)
                , m_authGate(m_sink, [] {})
            , m_configFetcher(m_config, m_performer, m_signer, m_clock, m_random, m_spoolFactory, m_authGate,
                              m_compressionGate)
            , m_wpkFetcher(m_config, m_performer, m_signer, m_clock, m_random, m_spoolFactory, m_authGate,
                           m_compressionGate)
            {
                ::mkdir(m_spoolDir.c_str(), 0700);
            }

            ~Downloader()
            {
                ::rmdir(m_spoolDir.c_str());
            }

            std::shared_ptr<SpoolFile> fetchConfig(const std::string& blob)
            {
                return m_configFetcher.fetch(sha256Hex(blob.data(), blob.size()), FAKE_MANAGER_CONFIG_TOKEN, m_waiter);
            }

            std::shared_ptr<SpoolFile> fetchWpk()
            {
                return m_wpkFetcher.fetch("wazuh_agent.wpk", "da39a3ee5e6b4b0d3255bfef95601890afd80709", m_waiter);
            }

            const std::vector<HttpResponse>& attempts() const
            {
                return m_performer.responses();
            }

            size_t filesLeft() const
            {
                return filesIn(m_spoolDir);
            }

        private:
            ModuleConfig m_config;
            std::string m_spoolDir;
            ConfigKeyProvider m_keyProvider {KEY_HEX};
            JwtSigner m_signer;
            CurlPerformer m_curl;
            RecordingPerformer m_performer;
            TempSpoolFactory m_spoolFactory;
            SystemClock m_clock;
            Mt19937Random m_random;
            CallbackDispatcher m_sink {hc_callbacks_t {}};
            AuthGate m_authGate;
            CompressionGate m_compressionGate;
            Waiter m_waiter;
            ConfigFetcher m_configFetcher;
            WpkFetcher m_wpkFetcher;
    };

    bool curlErrorIs(const HttpResponse& response, const std::string& code)
    {
        return response.curlError.rfind("(" + code + ")", 0) == 0;
    }
} // namespace

// The agent decodes with the libcurl inside libwazuhext. One built without zstd still sends
// Accept-Encoding: zstd and then fails every compressed download, so a stale tree has to fail here.
TEST(ConfigDownloadComponentTest, TheAgentsLibcurlDecodesZstd)
{
    const curl_version_info_data* info = curl_version_info(CURLVERSION_NOW);

    EXPECT_NE(0, info->features & CURL_VERSION_ZSTD)
            << "libcurl " << info->version << " was built without zstd: src/external/curl predates "
            "--with-zstd, run `make clean-deps` and `make deps` again";
}

TEST(ConfigDownloadComponentTest, AZstdReplyIsDecodedAndDeliveredByteForByte)
{
    const std::string blob = configBlob();
    const uint16_t port = DOWNLOAD_PORT;
    auto manager = downloadManager(port, blob, DownloadReply::Zstd);
    Downloader downloader {port};

    const auto file = downloader.fetchConfig(blob);

    ASSERT_NE(nullptr, file);
    EXPECT_TRUE(readFile(file->path()) == blob) << "the spooled file differs from the served config";
    EXPECT_EQ("zstd", acceptEncodingSeenBy(port));
    EXPECT_EQ(1u, downloader.attempts().size());
}

// What #40900's manager does when its memory budget has no room for the compressor, or when
// remoted.http_content_encoding_enabled is off: the offer is ignored and the reply goes plain.
TEST(ConfigDownloadComponentTest, APlainReplyToTheOfferIsDeliveredUnchanged)
{
    const std::string blob = configBlob();
    const uint16_t port = DOWNLOAD_PORT + 1;
    auto manager = downloadManager(port, blob, DownloadReply::Plain);
    Downloader downloader {port};

    const auto file = downloader.fetchConfig(blob);

    ASSERT_NE(nullptr, file);
    EXPECT_TRUE(readFile(file->path()) == blob) << "the spooled file differs from the served config";
    EXPECT_EQ("zstd", acceptEncodingSeenBy(port));
}

// curl rejects the frame (61) only after every decoded byte reached the file, so what keeps the
// body out is the transport error, not the hash. The attempt is retried once, like any other
// transport failure, and nothing is left in the spool directory.
TEST(ConfigDownloadComponentTest, ACorruptFrameIsDiscardedAfterOneRetry)
{
    const std::string blob = configBlob();
    const uint16_t port = DOWNLOAD_PORT + 2;
    auto manager = downloadManager(port, blob, DownloadReply::ZstdCorrupt);
    Downloader downloader {port};

    EXPECT_EQ(nullptr, downloader.fetchConfig(blob));
    ASSERT_EQ(2u, downloader.attempts().size()); // downloadMaxAttempts' default.

    for (const auto& attempt : downloader.attempts())
    {
        EXPECT_TRUE(curlErrorIs(attempt, "61")) << attempt.curlError;
    }

    EXPECT_EQ(0u, downloader.filesLeft());
}

// curl doesn't check that a frame ended: half a frame inside a properly terminated body is a
// successful transfer of a shorter config. Only config_hash stands between it and the agent.
TEST(ConfigDownloadComponentTest, ATruncatedFrameIsCaughtByTheConfigHash)
{
    const std::string blob = configBlob();
    const uint16_t port = DOWNLOAD_PORT + 3;
    auto manager = downloadManager(port, blob, DownloadReply::ZstdTruncatedFrame);
    Downloader downloader {port};

    EXPECT_EQ(nullptr, downloader.fetchConfig(blob));
    ASSERT_EQ(1u, downloader.attempts().size()); // A hash mismatch isn't a transport failure.
    EXPECT_EQ(TransportStatus::Ok, downloader.attempts().front().status);
    EXPECT_EQ(200, downloader.attempts().front().httpCode);
    EXPECT_EQ(0u, downloader.filesLeft());
}

// #40900's manager ends a stream whose source failed without the terminating chunk.
TEST(ConfigDownloadComponentTest, AStreamCutBeforeItsLastChunkIsDiscarded)
{
    const std::string blob = configBlob();
    const uint16_t port = DOWNLOAD_PORT + 4;
    auto manager = downloadManager(port, blob, DownloadReply::ZstdUnterminated);
    Downloader downloader {port};

    EXPECT_EQ(nullptr, downloader.fetchConfig(blob));
    ASSERT_EQ(2u, downloader.attempts().size());

    for (const auto& attempt : downloader.attempts())
    {
        // 18 on a clean close; 56 when OpenSSL 3 sees the socket close without close_notify.
        EXPECT_TRUE(curlErrorIs(attempt, "18") || curlErrorIs(attempt, "56")) << attempt.curlError;
    }

    EXPECT_EQ(0u, downloader.filesLeft());
}

TEST(ConfigDownloadComponentTest, TheWpkDownloadOffersNoEncoding)
{
    const uint16_t port = DOWNLOAD_PORT + 5;
    auto manager = downloadManager(port, configBlob(), DownloadReply::Zstd);
    Downloader downloader {port};

    EXPECT_EQ(nullptr, downloader.fetchWpk()); // The fake serves no WPK: a 404, after the header is seen.
    EXPECT_EQ("<absent>", acceptEncodingSeenBy(port));
}
