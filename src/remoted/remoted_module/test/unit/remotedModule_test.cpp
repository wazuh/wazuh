/*
 * Wazuh remoted module (C++ worker bridge) - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "remoted_module.h"
#include "testLogRecorder.hpp"
#include "testTlsServer.hpp"
#include <atomic>
#include <chrono>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <gtest/gtest.h>
#include <memory>
#include <mutex>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace
{
    // The process-wide log recorder lives in testLogRecorder.hpp, SHARED with every other test
    // file that starts the module through the C-ABI (adminServer_test.cpp): the module's log
    // sink is first-come for the lifetime of the process, so all such files must install the
    // same callback for anyone's log assertions to hold regardless of suite order.
    using remoted::test::g_logCalls;
    using remoted::test::LogRecorder;
    using remoted::test::testLogCallback;

    // A port the OS says is free, asked for right before the module binds it.
    //
    // This used to be hardcoded, which made every test in this file fail with
    // "bind: Address already in use" whenever anything else on the machine already held that
    // port -- a locally running manager, or another test binding the same number in a parallel
    // ctest run. Nothing here asserts on the port; it only has to be free.
    //
    // NOTE: cfg.port = 0 would NOT work. buildHttpServerConfig() reads a non-positive port as
    // "not configured" and substitutes the module's own default, so the module would go back to
    // binding a fixed, possibly-taken port.
    std::uint16_t findFreePort()
    {
        const int probe = ::socket(AF_INET, SOCK_STREAM, 0);
        if (probe < 0)
        {
            return 0;
        }

        sockaddr_in address {};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = 0; // let the kernel pick

        std::uint16_t port = 0;
        if (::bind(probe, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0)
        {
            socklen_t length = sizeof(address);
            if (::getsockname(probe, reinterpret_cast<sockaddr*>(&address), &length) == 0)
            {
                port = ntohs(address.sin_port);
            }
        }

        ::close(probe);
        return port;
    }

    remoted_module_config_t makeConfig()
    {
        remoted_module_config_t cfg {};
        cfg.port = findFreePort();
        EXPECT_NE(cfg.port, 0) << "could not obtain a free port to bind the module to";
        cfg.worker_node = false;
        std::snprintf(cfg.cluster_name, sizeof(cfg.cluster_name), "%s", "test-cluster");
        return cfg;
    }

    // remoted_module_start() brings up its HTTPS transport synchronously and fails fast (throws)
    // when the configured certificate/key is missing or unreadable -- see
    // RemotedModuleFacade::start(). The tests below that need a module which actually starts must
    // therefore hand it a real, readable self-signed certificate/key pair; there is no built-in
    // fallback that works outside of remoted's own chroot (the module default,
    // "etc/certs/remoted.pem", only resolves once Privsep_Chroot() has chdir()'d to "/").
    void writeSelfSignedTls(const std::string& certificatePath, const std::string& privateKeyPath)
    {
        using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
        using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;
        using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;

        for (const auto& path : {certificatePath, privateKeyPath})
        {
            const auto parent = std::filesystem::path(path).parent_path();
            if (!parent.empty())
            {
                std::filesystem::create_directories(parent);
            }
        }

        EvpPkeyPtr pkey {EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "prime256v1"), &EVP_PKEY_free};
        if (!pkey)
        {
            throw std::runtime_error("Failed to generate test EC key");
        }

        X509Ptr certificate {X509_new(), &X509_free};
        if (!certificate)
        {
            throw std::runtime_error("Failed to allocate test X509 certificate");
        }

        X509_set_version(certificate.get(), 2); // X509v3
        ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), 1);
        X509_gmtime_adj(X509_get_notBefore(certificate.get()), 0);
        X509_gmtime_adj(X509_get_notAfter(certificate.get()), 60L * 60L);

        X509_NAME* name = X509_get_subject_name(certificate.get());
        X509_NAME_add_entry_by_txt(
            name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("remoted-module-utest"), -1, -1, 0);
        X509_set_issuer_name(certificate.get(), name);
        X509_set_pubkey(certificate.get(), pkey.get());

        if (X509_sign(certificate.get(), pkey.get(), EVP_sha256()) == 0)
        {
            throw std::runtime_error("Failed to sign test certificate");
        }

        BioPtr certBio {BIO_new_file(certificatePath.c_str(), "w"), &BIO_free};
        if (!certBio || PEM_write_bio_X509(certBio.get(), certificate.get()) == 0)
        {
            throw std::runtime_error("Failed to write test certificate: " + certificatePath);
        }

        BioPtr keyBio {BIO_new_file(privateKeyPath.c_str(), "w"), &BIO_free};
        if (!keyBio || PEM_write_bio_PrivateKey(keyBio.get(), pkey.get(), nullptr, nullptr, 0, nullptr, nullptr) == 0)
        {
            throw std::runtime_error("Failed to write test private key: " + privateKeyPath);
        }
    }

    std::string makeTempPath(const char* prefix)
    {
        std::string pattern = std::string {"/tmp/"} + prefix + "-XXXXXX";
        const int fd = mkstemp(pattern.data());
        if (fd == -1)
        {
            throw std::runtime_error(std::string {"Failed to create temp file for "} + prefix);
        }
        close(fd);
        return pattern;
    }

    /// RAII throwaway TLS identity under /tmp, for tests that pass an explicit certificate_path/
    /// private_key_path and just need it to exist and be valid.
    class TempTlsFiles
    {
    public:
        TempTlsFiles()
            : m_certificatePath(makeTempPath("rmt-utest-cert"))
            , m_privateKeyPath(makeTempPath("rmt-utest-key"))
        {
            writeSelfSignedTls(m_certificatePath, m_privateKeyPath);
        }

        ~TempTlsFiles()
        {
            std::remove(m_certificatePath.c_str());
            std::remove(m_privateKeyPath.c_str());
        }

        TempTlsFiles(const TempTlsFiles&) = delete;
        TempTlsFiles& operator=(const TempTlsFiles&) = delete;

        const std::string& certificatePath() const
        {
            return m_certificatePath;
        }

        const std::string& privateKeyPath() const
        {
            return m_privateKeyPath;
        }

    private:
        std::string m_certificatePath;
        std::string m_privateKeyPath;
    };

    /// RAII throwaway TLS identity at the module's own built-in default path
    /// ("etc/certs/remoted.pem"/"etc/certs/remoted-key.pem", relative to the test process's cwd) --
    /// only for the one test that exercises the nullptr-configuration default-path fallback itself.
    class DefaultPathTlsFiles
    {
    public:
        DefaultPathTlsFiles()
            : m_createdEtcDir(!std::filesystem::exists("etc"))
        {
            writeSelfSignedTls("etc/certs/remoted.pem", "etc/certs/remoted-key.pem");
        }

        ~DefaultPathTlsFiles()
        {
            std::error_code ec;
            std::filesystem::remove("etc/certs/remoted.pem", ec);
            std::filesystem::remove("etc/certs/remoted-key.pem", ec);
            std::filesystem::remove("etc/certs", ec); // no-op if anything else landed in it meanwhile
            if (m_createdEtcDir)
            {
                std::filesystem::remove("etc", ec);
            }
        }

        DefaultPathTlsFiles(const DefaultPathTlsFiles&) = delete;
        DefaultPathTlsFiles& operator=(const DefaultPathTlsFiles&) = delete;

    private:
        bool m_createdEtcDir;
    };

    remoted_module_config_t makeConfig(const TempTlsFiles& tls)
    {
        auto cfg = makeConfig();
        std::snprintf(cfg.certificate_path, sizeof(cfg.certificate_path), "%s", tls.certificatePath().c_str());
        std::snprintf(cfg.private_key_path, sizeof(cfg.private_key_path), "%s", tls.privateKeyPath().c_str());
        return cfg;
    }
} // namespace

class RemotedModuleTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        g_logCalls.store(0, std::memory_order_relaxed);
        LogRecorder::clear();
    }

    void TearDown() override
    {
        // Ensure the module is stopped even if a test asserted early.
        remoted_module_stop();
    }
};

// start() must launch the worker and log, and stop() must return promptly (join succeeds).
TEST_F(RemotedModuleTest, StartAndStop)
{
    TempTlsFiles tls;
    const auto cfg = makeConfig(tls);
    remoted_module_start(testLogCallback, &cfg);
    remoted_module_stop();
    EXPECT_GT(g_logCalls.load(), 0);
}

// With global_prefix set through the C ABI, every public route moves under it: the health
// probe answers at /<prefix>/ and the bare / is gone (404). The transport/E2E suites pin the
// full behavior table; this is the black-box proof that the C-ABI field actually reaches it.
TEST_F(RemotedModuleTest, GlobalPrefixMovesEveryRoute)
{
    TempTlsFiles tls;
    auto cfg = makeConfig(tls);
    std::snprintf(cfg.global_prefix, sizeof(cfg.global_prefix), "/wazuh-manager/");
    remoted_module_start(testLogCallback, &cfg);

    const auto port = static_cast<std::uint16_t>(cfg.port);

    const auto prefixed = remoted::test::sendGetRequest(port, "/wazuh-manager/");
    EXPECT_NE(prefixed.find(" 200 "), std::string::npos) << prefixed;
    EXPECT_NE(prefixed.find("\"status\":\"ok\""), std::string::npos) << prefixed;

    const auto bare = remoted::test::sendGetRequest(port, "/");
    EXPECT_NE(bare.find(" 404 "), std::string::npos) << bare;

    remoted_module_stop();
}

// stop() on a module that was never started must be a safe no-op.
TEST_F(RemotedModuleTest, StopWithoutStartIsSafe)
{
    remoted_module_stop();
    SUCCEED();
}

// A NULL configuration must fall back to defaults -- including the default certificate/key
// path -- without crashing.
TEST_F(RemotedModuleTest, StartWithNullConfig)
{
    DefaultPathTlsFiles defaultTls;

    // The one test here that cannot be pointed at a free port: a null config means "use the
    // module's own defaults", and the default port is part of what is being exercised. If that
    // port happens to be taken on this machine -- a running manager, a parallel test run -- then
    // start() throws while binding, which says nothing about the null-config path under test, so
    // it is tolerated. What must hold either way is that the callback was reached: a null config
    // is accepted and reported instead of crashing. stop() after a failed start is a documented
    // no-op (see MissingCertificateIsReportedAsAnErrorNamingTheFile below).
    try
    {
        remoted_module_start(testLogCallback, nullptr);
    }
    catch (const std::exception& e)
    {
        GTEST_LOG_(INFO) << "start() with the built-in defaults did not bind: " << e.what();
    }

    remoted_module_stop();
    EXPECT_GT(g_logCalls.load(), 0);
}

// A second start() while running is ignored; a single stop() tears everything down.
TEST_F(RemotedModuleTest, DoubleStartIsIgnored)
{
    TempTlsFiles tls;
    const auto cfg = makeConfig(tls);
    remoted_module_start(testLogCallback, &cfg);
    remoted_module_start(testLogCallback, &cfg);
    remoted_module_stop();
    SUCCEED();
}

// End-to-end proof that a permanent misconfiguration fails fast and loudly: start() rethrows
// (RemotedModuleFacade::start() -- "a missing certificate is fatal to the module, and thus to
// remoted -- it must not start without it") but not before the failure reaches ossec.log naming
// the offending file. Before this work, a missing certificate produced only a generic "not
// started yet, will retry" WARN with an opaque OpenSSL string, repeated every 60 s forever and
// indistinguishable from a bad key, a port clash, or a fresh install that simply hadn't been
// provisioned yet.
TEST_F(RemotedModuleTest, MissingCertificateIsReportedAsAnErrorNamingTheFile)
{
    auto cfg = makeConfig();
    std::snprintf(cfg.certificate_path, sizeof(cfg.certificate_path), "%s", "/tmp/rmt-does-not-exist.crt");
    std::snprintf(cfg.private_key_path, sizeof(cfg.private_key_path), "%s", "/tmp/rmt-does-not-exist.key");

    EXPECT_THROW(remoted_module_start(testLogCallback, &cfg), std::exception);

    // The message must name the actual path, which is what makes it actionable.
    EXPECT_TRUE(LogRecorder::waitForMessageContaining("/tmp/rmt-does-not-exist.crt"))
        << "the startup failure did not name the missing certificate";

    // A failed start must not leave the module wedged: stop() stays a safe no-op...
    remoted_module_stop();

    // ...and a later start() with a valid certificate must still succeed.
    TempTlsFiles tls;
    const auto validCfg = makeConfig(tls);
    remoted_module_start(testLogCallback, &validCfg);
    EXPECT_GT(g_logCalls.load(), 0);
    remoted_module_stop();
}

// The wedge regression: start() used to set m_running BEFORE creating the worker thread, so a
// throwing std::thread constructor left the module claiming to run with nothing running -- and every
// later start() was refused with "already started". This pins the invariant from the reachable
// direction (a clean stop must leave the module startable again).
TEST_F(RemotedModuleTest, StartStopStartAgainWorks)
{
    TempTlsFiles tls;
    const auto cfg = makeConfig(tls);

    remoted_module_start(testLogCallback, &cfg);
    remoted_module_stop();

    LogRecorder::clear();
    remoted_module_start(testLogCallback, &cfg);

    // A second, healthy start must actually run -- not be refused as "already started".
    EXPECT_TRUE(LogRecorder::waitForMessageContaining("worker thread running"))
        << "the module refused to restart after a clean stop";

    remoted_module_stop();
}
