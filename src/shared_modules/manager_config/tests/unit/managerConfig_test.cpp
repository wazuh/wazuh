/*
 * Copyright (C) Wazuh Inc.
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */
#include <gtest/gtest.h>

#include <rapidjson/document.h>
#include <rapidjson/pointer.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <sstream>
#include <string>

#include <unistd.h>

#include "manager_config/manager_config.hpp"
#include "manager_config/manager_config_c.h"
#include "xmlToJson.hpp"

namespace
{

    const std::filesystem::path VECTORS {MANAGER_CONFIG_TEST_VECTORS};

    std::string slurp(const std::filesystem::path& file)
    {
        std::ifstream in(file);
        std::stringstream buffer;
        buffer << in.rdbuf();
        return buffer.str();
    }

    manager_config::LoadOptions noFiles()
    {
        manager_config::LoadOptions options;
        options.checkFiles = false;
        return options;
    }

    manager_config::Document parseOk(const std::string& xml)
    {
        auto result = manager_config::Document::parse(xml, noFiles());
        if (auto* error = std::get_if<manager_config::Error>(&result))
        {
            ADD_FAILURE() << "unexpected error: " << error->what();
        }
        return std::move(std::get<manager_config::Document>(result));
    }

    manager_config::Error parseKo(const std::string& xml)
    {
        auto result = manager_config::Document::parse(xml, noFiles());
        if (std::holds_alternative<manager_config::Document>(result))
        {
            ADD_FAILURE() << "expected an error";
            return {};
        }
        return std::get<manager_config::Error>(result);
    }

    rapidjson::Document json(const std::string& text)
    {
        rapidjson::Document doc;
        doc.Parse(text.c_str());
        EXPECT_FALSE(doc.HasParseError()) << text;
        return doc;
    }

    // The two schema-mandatory sections, spelled out once for tests that only care about some other part
    // of the document.
    const char* const CLUSTER_SECTION = "<cluster><key>0123456789abcdef0123456789abcdef</key></cluster>";
    const char* const INDEXER_SECTION = "<indexer><hosts><host>https://127.0.0.1:9200</host></hosts></indexer>";

    std::string wrap(const std::string& body)
    {
        return "<wazuh_config>" + body + CLUSTER_SECTION + INDEXER_SECTION + "</wazuh_config>";
    }

    /// The five checked certificate/key options, spelled out under `dir`. The defaults are absolute
    /// (/etc/wazuh-manager/certs/...), so a file-checking test that relied on them would look at the build
    /// host's real configuration directory.
    std::string certificates(const std::string& dir,
                             const std::string& certificate = "remoted.pem",
                             const std::string& caCertificate = "root-ca.pem")
    {
        return "<remote><https><certificate>" + dir + "/" + certificate + "</certificate><key>" + dir +
               "/remoted-key.pem</key><ca_certificate>" + dir + "/" + caCertificate +
               "</ca_certificate></https></remote><auth><ssl_manager_cert>" + dir +
               "/remoted.pem</ssl_manager_cert><ssl_manager_key>" + dir + "/remoted-key.pem</ssl_manager_key></auth>";
    }

} // namespace

// ---------------------------------------------------------------------------------------------------
// Load / defaults
// ---------------------------------------------------------------------------------------------------

TEST(Load, EffectiveDefaultsFromMinimalDocument)
{
    const auto doc = parseOk(slurp(VECTORS / "valid" / "minimal-valid.conf"));
    const auto effective = json(doc.documentJson());
    for (const char* section : {"global",
                                "logging",
                                "remote",
                                "auth",
                                "wdb",
                                "vulnerability-detection",
                                "indexer",
                                "task-manager",
                                "cluster"})
    {
        EXPECT_TRUE(effective.HasMember(section)) << section;
    }
    EXPECT_STREQ(rapidjson::Pointer("/global/agents_disconnection_time").Get(effective)->GetString(), "15m");
    EXPECT_EQ(rapidjson::Pointer("/global/agents_disconnection_alert_time").Get(effective), nullptr);
    EXPECT_STREQ(rapidjson::Pointer("/logging/log_format/0").Get(effective)->GetString(), "plain");
    // absent legacy block = disabled listener, but every option still has a value
    EXPECT_FALSE(rapidjson::Pointer("/remote/legacy/enabled").Get(effective)->GetBool());
    EXPECT_EQ(rapidjson::Pointer("/remote/legacy/port").Get(effective)->GetInt(), 1514);
    EXPECT_EQ(rapidjson::Pointer("/remote/https/port").Get(effective)->GetInt(), 1517);
    EXPECT_STREQ(rapidjson::Pointer("/remote/https/global_prefix").Get(effective)->GetString(), "/wazuh-manager/");
    EXPECT_STREQ(rapidjson::Pointer("/remote/https/ca_certificate").Get(effective)->GetString(),
                 "/etc/wazuh-manager/certs/root-ca.pem");
    EXPECT_STREQ(rapidjson::Pointer("/remote/https/certificate").Get(effective)->GetString(),
                 "/etc/wazuh-manager/certs/remoted.pem");
    EXPECT_STREQ(rapidjson::Pointer("/remote/https/key").Get(effective)->GetString(),
                 "/etc/wazuh-manager/certs/remoted-key.pem");
    EXPECT_STREQ(rapidjson::Pointer("/auth/ssl_manager_cert").Get(effective)->GetString(),
                 "/etc/wazuh-manager/certs/remoted.pem");
    EXPECT_STREQ(rapidjson::Pointer("/auth/ssl_manager_key").Get(effective)->GetString(),
                 "/etc/wazuh-manager/certs/remoted-key.pem");
    EXPECT_EQ(rapidjson::Pointer("/remote/https/verification_mode").Get(effective), nullptr) << "no default: absent";
    // The rate limits are NOT written into the shipped file, but they do have defaults: an absent
    // option must arrive at remoted as a real value, never as "unlimited".
    EXPECT_EQ(rapidjson::Pointer("/remote/https/enroll_rate_limit").Get(effective)->GetInt(), 100);
    EXPECT_EQ(rapidjson::Pointer("/remote/https/cacerts_rate_limit").Get(effective)->GetInt(), 50);
    // The values remoted_module applies anyway, declared so the effective document shows them.
    EXPECT_STREQ(rapidjson::Pointer("/remote/https/ciphers").Get(effective)->GetString(),
                 "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256");
    EXPECT_STREQ(rapidjson::Pointer("/remote/https/max_body_size").Get(effective)->GetString(), "10M");
    EXPECT_FALSE(rapidjson::Pointer("/remote/https/dual_stack").Get(effective)->GetBool());
    EXPECT_EQ(rapidjson::Pointer("/auth/port").Get(effective)->GetInt(), 1515);
    EXPECT_EQ(rapidjson::Pointer("/auth/legacy_enrollment").Get(effective), nullptr)
        << "no default: authd follows remote.legacy.enabled when unset";
    EXPECT_TRUE(rapidjson::Pointer("/auth/force/disconnected_time/enabled").Get(effective)->GetBool());
    EXPECT_STREQ(rapidjson::Pointer("/wdb/backup/global/interval").Get(effective)->GetString(), "1d");
    EXPECT_EQ(rapidjson::Pointer("/vulnerability-detection/pageSize").Get(effective)->GetInt(), 100);
    EXPECT_EQ(rapidjson::Pointer("/indexer/hosts").Get(effective)->Size(), 1u);
    EXPECT_STREQ(rapidjson::Pointer("/indexer/hosts/0").Get(effective)->GetString(), "https://127.0.0.1:9200");
    EXPECT_EQ(rapidjson::Pointer("/task-manager/task_ttl").Get(effective)->GetInt(), 3600);
    // Agent upgrades are the task manager's on a manager; there is no `agent-upgrade` section.
    EXPECT_FALSE(effective.HasMember("agent-upgrade"));
    EXPECT_TRUE(rapidjson::Pointer("/task-manager/upgrade_enabled").Get(effective)->GetBool());
    EXPECT_EQ(rapidjson::Pointer("/task-manager/wpk_repository").Get(effective), nullptr)
        << "no default: the repository is picked from the target agent version";
    EXPECT_STREQ(rapidjson::Pointer("/cluster/node_type").Get(effective)->GetString(), "master");
    EXPECT_EQ(rapidjson::Pointer("/cluster/nodes").Get(effective)->Size(), 1u);
}

TEST(Load, PresentLegacyBlockIsEnabledByDefault)
{
    const auto doc = parseOk(wrap("<remote><legacy><port>1514</port></legacy></remote>"));
    const auto remote = json(doc.sectionJson("remote"));
    EXPECT_TRUE(rapidjson::Pointer("/legacy/enabled").Get(remote)->GetBool());
    EXPECT_STREQ(rapidjson::Pointer("/legacy/protocol/0").Get(remote)->GetString(), "tcp");
}

TEST(Load, GeneratedManagerFileKeepsUserValuesAndFillsTheRest)
{
    const auto doc = parseOk(slurp(VECTORS / "valid" / "generated-manager.conf"));
    const auto remote = json(doc.sectionJson("remote"));
    EXPECT_TRUE(rapidjson::Pointer("/legacy/enabled").Get(remote)->GetBool());
    EXPECT_EQ(rapidjson::Pointer("/legacy/queue_size").Get(remote)->GetInt(), 131072) << "written by the installer";
    EXPECT_EQ(rapidjson::Pointer("/legacy/connection_overtake_time").Get(remote)->GetInt(), 60) << "filled default";
    EXPECT_STREQ(rapidjson::Pointer("/https/certificate").Get(remote)->GetString(),
                 "/etc/wazuh-manager/certs/remoted.pem");
    EXPECT_STREQ(rapidjson::Pointer("/https/ca_certificate").Get(remote)->GetString(),
                 "/etc/wazuh-manager/certs/root-ca.pem");
    EXPECT_EQ(remote["https"].MemberCount(), 12u) << "port, bind_addr, global_prefix, certificate, key, ca, "
                                                     "ca_certificate, ciphers, max_body_size, dual_stack and the "
                                                     "two rate limits (verification_mode has no default and "
                                                     "stays absent)";
    const auto auth = json(doc.sectionJson("auth"));
    EXPECT_TRUE(auth["purge"].GetBool());
    EXPECT_TRUE(auth["use_password"].GetBool());
    EXPECT_EQ(auth.MemberCount(), 14u) << "12 defaulted leaves + force + agents objects (18 inventory options; "
                                          "legacy_enrollment has no default)";
    const auto indexer = json(doc.sectionJson("indexer"));
    EXPECT_STREQ(rapidjson::Pointer("/hosts/0").Get(indexer)->GetString(), "https://127.0.0.1:9200");
    EXPECT_STREQ(rapidjson::Pointer("/ssl/certificate_authorities/0").Get(indexer)->GetString(),
                 "/etc/wazuh-manager/certs/indexer-ca.pem");
}

TEST(Load, EveryValidVectorLoads)
{
    for (const auto& entry : std::filesystem::directory_iterator(VECTORS / "valid"))
    {
        auto result = manager_config::Document::parse(slurp(entry.path()), noFiles());
        EXPECT_TRUE(std::holds_alternative<manager_config::Document>(result))
            << entry.path().filename() << ": " << std::get<manager_config::Error>(result).what();
    }
}

TEST(Load, DurationsAcceptIntegersAndStrings)
{
    const auto doc = parseOk(slurp(VECTORS / "valid" / "durations-as-integers.conf"));
    const auto global = json(doc.sectionJson("global"));
    EXPECT_EQ(global["agents_disconnection_time"].GetInt(), 900);
    EXPECT_EQ(rapidjson::Pointer("/backup/global/interval").Get(json(doc.sectionJson("wdb")))->GetInt(), 3600);
}

TEST(Load, UnknownSectionQueryIsEmpty)
{
    const auto doc = parseOk(wrap(""));
    EXPECT_TRUE(doc.sectionJson("syscheck").empty());
    EXPECT_FALSE(doc.hasSection("wodle"));
    EXPECT_TRUE(doc.hasSection("cluster"));
}

TEST(Load, MissingFileIsAnError)
{
    auto error = manager_config::validateFile(VECTORS / "does-not-exist.conf", noFiles());
    ASSERT_TRUE(error.has_value());
    EXPECT_NE(error->message.find("not found"), std::string::npos);
}

TEST(Load, UnreadablePathReportsTheSystemErrorNotNotFound)
{
    // A directory stands in for every access error that is not ENOENT (a permission error cannot be produced
    // reliably when the suite runs as root).
    auto error = manager_config::validateFile(VECTORS, noFiles());
    ASSERT_TRUE(error.has_value());
    EXPECT_EQ(error->message.find("not found"), std::string::npos) << error->what();
    EXPECT_NE(error->message.find("cannot be read: " + VECTORS.string() + ": "), std::string::npos) << error->what();
}

TEST(Load, UnopenableFileNamesTheReason)
{
    // A regular file the caller may not open: the message carries open()'s reason, as for every other access error.
    if (::geteuid() == 0)
    {
        GTEST_SKIP() << "root opens a file whatever its mode";
    }
    const auto file =
        std::filesystem::temp_directory_path() / ("manager_config_unopenable_" + std::to_string(::getpid()));
    std::ofstream(file) << "<wazuh_config/>";
    std::filesystem::permissions(file, std::filesystem::perms::none);
    auto error = manager_config::validateFile(file, noFiles());
    std::filesystem::remove(file);
    ASSERT_TRUE(error.has_value());
    EXPECT_NE(error->message.find("cannot be read: " + file.string() + ": Permission denied"), std::string::npos)
        << error->what();
}

// ---------------------------------------------------------------------------------------------------
// Schema and XML-level rejections, driven by the shared vectors
// ---------------------------------------------------------------------------------------------------

TEST(Schema, EveryInvalidVectorFailsWithTheExpectedPointerAndKeyword)
{
    std::size_t vectors = 0;
    for (const auto& entry : std::filesystem::directory_iterator(VECTORS / "invalid"))
    {
        ++vectors;
        const auto name = entry.path().stem().string();
        const auto expected = json(slurp(VECTORS / "expected" / (name + ".json")));
        const auto error = parseKo(slurp(entry.path()));
        EXPECT_EQ(error.pointer, std::string {expected["pointer"].GetString()}) << name << ": " << error.what();
        const std::string keyword = expected["keyword"].GetString();
        if (keyword != "xml" && keyword != "semantics")
        {
            EXPECT_NE(error.message.find(keyword), std::string::npos) << name << ": " << error.what();
        }
    }
    EXPECT_GE(vectors, 24u);
}

TEST(Schema, YesNoIsBooleanAndTrueFalseIsRejected)
{
    const auto doc = parseOk(wrap("<auth><use_password>yes</use_password></auth>"));
    EXPECT_TRUE(json(doc.sectionJson("auth"))["use_password"].GetBool());
    const auto error = parseKo(wrap("<auth><use_password>true</use_password></auth>"));
    EXPECT_EQ(error.pointer, "/auth/use_password");
    EXPECT_NE(error.message.find("type"), std::string::npos) << error.what();
    EXPECT_NE(error.message.find("booleans are yes/no"), std::string::npos) << error.what();
}

TEST(Schema, UnknownTopLevelOptionNamesTheSchemaRoot)
{
    // The rule broken is the root's additionalProperties, whose schema pointer is empty: never "[schema ]".
    const auto error = parseKo(wrap("<github><enabled>yes</enabled></github>"));
    EXPECT_EQ(error.pointer, "/github");
    EXPECT_NE(error.message.find("[schema /]"), std::string::npos) << error.what();
    EXPECT_EQ(error.message.find("[schema ]"), std::string::npos) << error.what();
}

TEST(Schema, BooleanHintOnlyForBooleanOptions)
{
    // An integer option given text is a type error too, but not a boolean one.
    const auto error = parseKo(wrap("<remote><https><port>abc</port></https></remote>"));
    EXPECT_EQ(error.pointer, "/remote/https/port");
    EXPECT_NE(error.message.find("does not satisfy 'type'"), std::string::npos) << error.what();
    EXPECT_EQ(error.message.find("yes/no"), std::string::npos) << error.what();
}

TEST(Schema, CiphersAcceptOnlyTheSuitesTheDaemonsAccept)
{
    // remoted and authd accept exactly these five TLS 1.3 suites; a well-formed name outside them must fail
    // here, not at a daemon's configuration test.
    parseOk(wrap("<auth><ciphers>TLS_AES_128_CCM_8_SHA256:TLS_AES_128_CCM_SHA256</ciphers></auth>"
                 "<remote><https><ciphers>TLS_AES_128_GCM_SHA256</ciphers></https></remote>"));
    for (const char* ciphers : {"TLS_SM4_GCM_SM3", "TLS_AES_128_GCM_SHA256:", "TLS_AES_128_GCM_SHA256X"})
    {
        const auto auth = parseKo(wrap(std::string("<auth><ciphers>") + ciphers + "</ciphers></auth>"));
        EXPECT_EQ(auth.pointer, "/auth/ciphers") << ciphers;
        EXPECT_NE(auth.message.find("pattern"), std::string::npos) << auth.what();
        const auto remote =
            parseKo(wrap(std::string("<remote><https><ciphers>") + ciphers + "</ciphers></https></remote>"));
        EXPECT_EQ(remote.pointer, "/remote/https/ciphers") << ciphers;
    }
}

TEST(Schema, IpOptionsAcceptOnlyWhatRemotedAccepts)
{
    // The addresses remoted's reader takes for remote.legacy.local_ip and remote.https.bind_addr: one IPv4 or
    // IPv6 address, no CIDR prefix, netmask, host name or 'any'. Anything else used to pass validate and stop
    // remoted at its configuration test.
    for (const char* address : {"0.0.0.0",
                                "127.0.0.1",
                                "255.255.255.255",
                                "::",
                                "::1",
                                "fe80::1",
                                "2001:db8::",
                                "1:2:3:4:5:6:7:8",
                                "1:2:3:4:5:6::8",
                                "::ffff:10.0.0.1",
                                "::FFFF:10.0.0.1"})
    {
        parseOk(wrap(std::string("<remote><https><bind_addr>") + address + "</bind_addr></https><legacy><local_ip>" +
                     address + "</local_ip></legacy></remote>"));
    }
    for (const char* address : {"not-an-ip",
                                "999.1.1.1",
                                "256.0.0.1",
                                "01.2.3.4",
                                "1.2.3",
                                "1.2.3.4.5",
                                "10.0.0.0/8",
                                "10.0.0.1/255.0.0.0",
                                "::1/128",
                                "1::2::3",
                                ":::",
                                "12345::",
                                "1:2:3:4:5:6:7:8:9",
                                "any",
                                "localhost",
                                "!10.0.0.1"})
    {
        const auto https =
            parseKo(wrap(std::string("<remote><https><bind_addr>") + address + "</bind_addr></https></remote>"));
        EXPECT_EQ(https.pointer, "/remote/https/bind_addr") << address;
        EXPECT_NE(https.message.find("pattern"), std::string::npos) << https.what();
        const auto legacy =
            parseKo(wrap(std::string("<remote><legacy><local_ip>") + address + "</local_ip></legacy></remote>"));
        EXPECT_EQ(legacy.pointer, "/remote/legacy/local_ip") << address;
    }
    // clusterd binds through Python's asyncio, which also resolves a host name: cluster.bind_addr takes one
    // (Schema.ClusterBindAddrIsAHostAndIndexerHostsNameOne).
    parseOk("<wazuh_config><cluster><key>0123456789abcdef0123456789abcdef</key><bind_addr>localhost</bind_addr>"
            "</cluster>" +
            std::string(INDEXER_SECTION) + "</wazuh_config>");
}

TEST(Schema, ClusterBindAddrIsAHostAndIndexerHostsNameOne)
{
    const auto cluster = [](const std::string& address)
    {
        return "<wazuh_config><cluster><key>0123456789abcdef0123456789abcdef</key><bind_addr>" + address +
               "</bind_addr></cluster>" + std::string(INDEXER_SECTION) + "</wazuh_config>";
    };
    for (const char* address :
         {"0.0.0.0", "127.0.0.1", "::", "fe80::1", "localhost", "wazuh_master", "node-1.example.com", "a.b."})
    {
        parseOk(cluster(address));
    }
    for (const char* address : {"not a host!", "-leading-dash", "host:1516", "a..b", "10.0.0.0/8"})
    {
        const auto error = parseKo(cluster(address));
        EXPECT_EQ(error.pointer, "/cluster/bind_addr") << address;
        EXPECT_NE(error.message.find("pattern"), std::string::npos) << error.what();
    }

    const auto indexer = [](const std::string& host)
    {
        return "<wazuh_config>" + std::string(CLUSTER_SECTION) + "<indexer><hosts><host>" + host +
               "</host></hosts></indexer></wazuh_config>";
    };
    for (const char* host : {"https://127.0.0.1:9200",
                             "http://localhost",
                             "https://indexer-1.example.com:9200/",
                             "https://[::1]:9200",
                             "https://[fd00::5]/prefix"})
    {
        parseOk(indexer(host));
    }
    for (const char* host : {"https://", "http://:9200", "https://not a host", "https://host:", "localhost:9200"})
    {
        const auto error = parseKo(indexer(host));
        EXPECT_EQ(error.pointer, "/indexer/hosts/0") << host;
    }
}

TEST(Schema, DurationsAndSizesStopWhereTheReadersWould)
{
    // w_parse_time() and w_parse_size() overflow, and their consumers keep an int, past these spellings; a zero
    // with a unit is still zero, which every reader below refuses.
    parseOk(wrap("<global><agents_disconnection_time>999w</agents_disconnection_time></global>"
                 "<remote><legacy><rids_closing_time>999999999</rids_closing_time></legacy>"
                 "<https><max_body_size>1G</max_body_size></https></remote>"
                 "<wdb><backup database=\"global\"><interval>9999d</interval></backup></wdb>"));
    const struct
    {
        const char* body;
        const char* pointer;
    } rejected[] = {
        {"<global><agents_disconnection_time>15250284452472w</agents_disconnection_time></global>",
         "/global/agents_disconnection_time"},
        {"<global><agents_disconnection_time>1000w</agents_disconnection_time></global>",
         "/global/agents_disconnection_time"},
        {"<global><agents_disconnection_time>1000000000</agents_disconnection_time></global>",
         "/global/agents_disconnection_time"},
        {"<remote><legacy><rids_closing_time>0m</rids_closing_time></legacy></remote>",
         "/remote/legacy/rids_closing_time"},
        {"<remote><legacy><rids_closing_time>0</rids_closing_time></legacy></remote>",
         "/remote/legacy/rids_closing_time"},
        {"<remote><https><max_body_size>0K</max_body_size></https></remote>", "/remote/https/max_body_size"},
        {"<remote><https><max_body_size>1000000G</max_body_size></https></remote>", "/remote/https/max_body_size"},
        {"<remote><https><max_body_size>2G</max_body_size></https></remote>", "/remote/https/max_body_size"},
        {"<wdb><backup database=\"global\"><interval>99999999999999999999</interval></backup></wdb>",
         "/wdb/backup/global/interval"},
        {"<vulnerability-detection><feed-update-interval>99999999m</feed-update-interval></vulnerability-detection>",
         "/vulnerability-detection/feed-update-interval"},
        {"<auth><force><after_registration_time>100000d</after_registration_time></force></auth>",
         "/auth/force/after_registration_time"},
    };
    for (const auto& item : rejected)
    {
        EXPECT_EQ(parseKo(wrap(item.body)).pointer, item.pointer) << item.body;
    }
}

TEST(Schema, HttpsMaxBodySizeIsCappedAtOneGibibyte)
{
    // The read phase buffers up to one body per connection, so the cap bounds that peak; 1G in every spelling.
    for (const char* size : {"1G", "1g", "1024M", "1048576K", "1073741824", "1073741824B", "0001G", "1"})
    {
        parseOk(wrap(std::string("<remote><https><max_body_size>") + size + "</max_body_size></https></remote>"));
    }
    for (const char* size : {"2G", "1025M", "1048577K", "1073741825", "1073741825B", "10737418240", "0G"})
    {
        const auto error =
            parseKo(wrap(std::string("<remote><https><max_body_size>") + size + "</max_body_size></https></remote>"));
        EXPECT_EQ(error.pointer, "/remote/https/max_body_size") << size;
    }
}

TEST(Schema, HttpsStringsAreCappedAtRemotedBufferSizes)
{
    // remote-config.h caps these at 255 and 511 characters (one less than remoted_module's C buffers).
    const std::string prefix = "/" + std::string(254, 'a');
    parseOk(wrap("<remote><https><global_prefix>" + prefix + "</global_prefix></https></remote>"));
    const auto longPrefix =
        parseKo(wrap("<remote><https><global_prefix>" + prefix + "a</global_prefix></https></remote>"));
    EXPECT_EQ(longPrefix.pointer, "/remote/https/global_prefix");
    EXPECT_NE(longPrefix.message.find("maxLength"), std::string::npos) << longPrefix.what();

    const std::string path = "/" + std::string(510, 'p');
    for (const char* option : {"ca", "ca_certificate"})
    {
        parseOk(wrap(std::string("<remote><https><") + option + ">" + path + "</" + option + "></https></remote>"));
        const auto error = parseKo(
            wrap(std::string("<remote><https><") + option + ">" + path + "p</" + option + "></https></remote>"));
        EXPECT_EQ(error.pointer, std::string("/remote/https/") + option);
        EXPECT_NE(error.message.find("maxLength"), std::string::npos) << error.what();
    }
    const auto key =
        parseKo(wrap("<remote><https><certificate>/c.pem</certificate><key>" + path + "p</key></https></remote>"));
    EXPECT_EQ(key.pointer, "/remote/https/key");

    std::string ciphers = "TLS_AES_128_GCM_SHA256";
    while (ciphers.size() <= 255)
    {
        ciphers += ":TLS_AES_128_GCM_SHA256";
    }
    const auto longCiphers = parseKo(wrap("<remote><https><ciphers>" + ciphers + "</ciphers></https></remote>"));
    EXPECT_EQ(longCiphers.pointer, "/remote/https/ciphers");
    EXPECT_NE(longCiphers.message.find("maxLength"), std::string::npos) << longCiphers.what();
}

TEST(Schema, FeedUpdateIntervalRejectsZeroInAnyUnit)
{
    EXPECT_EQ(parseKo(wrap("<vulnerability-detection><feed-update-interval>0m</feed-update-interval>"
                           "</vulnerability-detection>"))
                  .pointer,
              "/vulnerability-detection/feed-update-interval");
    EXPECT_EQ(parseKo(wrap("<vulnerability-detection><feed-update-interval>0</feed-update-interval>"
                           "</vulnerability-detection>"))
                  .pointer,
              "/vulnerability-detection/feed-update-interval");
    parseOk(wrap("<vulnerability-detection><feed-update-interval>1</feed-update-interval></vulnerability-detection>"));
}

TEST(Schema, RejectsUnknownKeyPointingAtTheKey)
{
    EXPECT_EQ(parseKo("<wazuh_config><remote><https><foo>1</foo></https></remote></wazuh_config>").pointer,
              "/remote/https/foo");
    EXPECT_EQ(parseKo("<wazuh_config><syscheck></syscheck></wazuh_config>").pointer, "/syscheck");
}

// ---------------------------------------------------------------------------------------------------
// XML dialect: typing, attribute forms, lists
// ---------------------------------------------------------------------------------------------------

TEST(Xml, CsvAndRepeatedElementsBecomeArrays)
{
    const auto csv = parseOk(wrap("<logging><log_format>plain, json</log_format></logging>"));
    const auto logging = json(csv.sectionJson("logging"));
    ASSERT_EQ(logging["log_format"].Size(), 2u);
    EXPECT_STREQ(logging["log_format"][1].GetString(), "json");
    const auto repeated =
        parseOk(wrap("<logging><log_format>plain</log_format><log_format>json</log_format></logging>"));
    EXPECT_EQ(json(repeated.sectionJson("logging"))["log_format"].Size(), 2u);
    const auto wrapper = parseOk(std::string("<wazuh_config><indexer><hosts><host>https://a:9200</host>"
                                             "<host>https://b:9200</host></hosts></indexer>") +
                                 CLUSTER_SECTION + "</wazuh_config>");
    const auto indexer = json(wrapper.sectionJson("indexer"));
    ASSERT_EQ(indexer["hosts"].Size(), 2u);
    EXPECT_STREQ(indexer["hosts"][1].GetString(), "https://b:9200");
}

TEST(Xml, AttributeFormsBecomeNestedObjects)
{
    const auto doc = parseOk(wrap("<wdb><backup database=\"global\"><enabled>no</enabled>"
                                  "<interval>1d</interval><max_files>3</max_files></backup></wdb>"
                                  "<auth><force><disconnected_time enabled=\"yes\">1h</disconnected_time>"
                                  "</force></auth>"));
    const auto wdb = json(doc.sectionJson("wdb"));
    EXPECT_FALSE(rapidjson::Pointer("/backup/global/enabled").Get(wdb)->GetBool());
    EXPECT_STREQ(rapidjson::Pointer("/backup/global/interval").Get(wdb)->GetString(), "1d");
    const auto auth = json(doc.sectionJson("auth"));
    EXPECT_TRUE(rapidjson::Pointer("/force/disconnected_time/enabled").Get(auth)->GetBool());
    EXPECT_STREQ(rapidjson::Pointer("/force/disconnected_time/value").Get(auth)->GetString(), "1h");
}

TEST(Xml, EntitiesAreDecodedAndEnumsNormalized)
{
    const auto doc = parseOk(std::string("<wazuh_config><cluster><name>a&amp;b</name>"
                                         "<key>0123456789abcdef0123456789abcdef</key></cluster>"
                                         "<remote><legacy><protocol>TCP,UDP</protocol></legacy>"
                                         "<https><verification_mode>Full</verification_mode></https></remote>") +
                             INDEXER_SECTION + "</wazuh_config>");
    EXPECT_STREQ(json(doc.sectionJson("cluster"))["name"].GetString(), "a&b");
    const auto remote = json(doc.sectionJson("remote"));
    EXPECT_STREQ(rapidjson::Pointer("/legacy/protocol/0").Get(remote)->GetString(), "tcp");
    EXPECT_STREQ(rapidjson::Pointer("/legacy/protocol/1").Get(remote)->GetString(), "udp");
    EXPECT_STREQ(rapidjson::Pointer("/https/verification_mode").Get(remote)->GetString(), "full");
}

TEST(Xml, RejectsRawAmpersandSecondRootLegacyCommentAndWrongRoot)
{
    const auto amp = parseKo("<wazuh_config><cluster><name>a & b</name></cluster></wazuh_config>");
    EXPECT_TRUE(amp.pointer.empty());
    EXPECT_NE(amp.message.find("raw '&'"), std::string::npos) << amp.what();
    EXPECT_NE(amp.message.find("line 1"), std::string::npos) << amp.what();
    const auto second = parseKo("<wazuh_config></wazuh_config>\n<wazuh_config></wazuh_config>");
    EXPECT_NE(second.message.find("exactly one <wazuh_config>"), std::string::npos) << second.what();
    EXPECT_NE(second.message.find("line 2"), std::string::npos) << second.what();
    EXPECT_NE(parseKo("<wazuh_config><! legacy comment !></wazuh_config>").message.find("invalid XML"),
              std::string::npos);
    EXPECT_NE(parseKo("<wazuh_config><!-- a -- b --></wazuh_config>").message.find("'--'"), std::string::npos);
    EXPECT_NE(parseKo("<ossec_config></ossec_config>").message.find("must be <wazuh_config>"), std::string::npos);
    EXPECT_NE(parseKo("").message.find("invalid XML"), std::string::npos) << "an empty file has no root";
}

TEST(Xml, EveryDocumentLevelRejectionIsMarkedAsInvalidXml)
{
    // A document-level rejection has no JSON pointer, so the "invalid XML" prefix is the only thing that
    // tells a consumer it is a syntax problem and not a schema violation: the framework reports the former
    // as 1131 and the latter as 1130, whose remediation names a pointer these errors do not have.
    for (const char* document : {"<wazuh_config><cluster><name>a & b</name></cluster></wazuh_config>",
                                 "<wazuh_config><!-- a -- b --></wazuh_config>",
                                 "<wazuh_config></wazuh_config>\n<wazuh_config></wazuh_config>",
                                 "<ossec_config></ossec_config>",
                                 "<wazuh_config version=\"5.0\"></wazuh_config>",
                                 "<!-- only a comment -->",
                                 "not xml at all",
                                 ""})
    {
        const auto error = parseKo(document);
        EXPECT_TRUE(error.pointer.empty()) << document << ": " << error.what();
        EXPECT_EQ(error.message.rfind("invalid XML: ", 0), 0u) << document << ": " << error.what();
    }
}

TEST(Xml, RejectsDuplicatesStrayTextAndWrongListItems)
{
    const auto duplicate = parseKo("<wazuh_config><auth><port>1515</port><port>1516</port></auth></wazuh_config>");
    EXPECT_EQ(duplicate.pointer, "/auth/port");
    EXPECT_NE(duplicate.message.find("duplicate"), std::string::npos) << duplicate.what();
    const auto text = parseKo("<wazuh_config><auth>stray<port>1515</port></auth></wazuh_config>");
    EXPECT_EQ(text.pointer, "/auth");
    EXPECT_NE(text.message.find("unexpected text"), std::string::npos) << text.what();
    const auto item =
        parseKo("<wazuh_config><indexer><hosts><url>https://a:9200</url></hosts></indexer></wazuh_config>");
    EXPECT_EQ(item.pointer, "/indexer/hosts");
    EXPECT_NE(item.message.find("expected <host>"), std::string::npos) << item.what();
}

TEST(Xml, RejectsOversizeAndDepth)
{
    std::string big = "<wazuh_config>";
    big.append(manager_config::detail::MAX_XML_BYTES + 1, ' ');
    big += "</wazuh_config>";
    EXPECT_NE(parseKo(big).message.find("larger than"), std::string::npos);
    std::string deep;
    std::string closers;
    for (int i = 0; i < manager_config::detail::MAX_XML_DEPTH + 1; ++i)
    {
        deep += "<k" + std::to_string(i) + ">";
        closers = "</k" + std::to_string(i) + ">" + closers;
    }
    EXPECT_NE(parseKo("<wazuh_config>" + deep + "v" + closers + "</wazuh_config>").message.find("deeper"),
              std::string::npos);
}

// ---------------------------------------------------------------------------------------------------
// Semantics
// ---------------------------------------------------------------------------------------------------

TEST(Semantics, CertificateWithoutKeyAndPortCollisionsAndDotSegments)
{
    EXPECT_EQ(parseKo(wrap("<remote><https><certificate>a.pem</certificate><key></key></https></remote>")).pointer,
              "/remote/https/key");
    EXPECT_EQ(
        parseKo(wrap("<remote><legacy><port>1515</port></legacy></remote><auth><port>1515</port></auth>")).pointer,
        "/auth/port");
    EXPECT_EQ(parseKo(std::string("<wazuh_config><cluster><key>0123456789abcdef0123456789abcdef</key>"
                                  "<port>1517</port></cluster>") +
                      INDEXER_SECTION + "</wazuh_config>")
                  .pointer,
              "/cluster/port")
        << "collides with remote.https.port default";
    EXPECT_EQ(parseKo(wrap("<remote><https><global_prefix>/a/../b/</global_prefix></https></remote>")).pointer,
              "/remote/https/global_prefix");
    // a disabled listener does not reserve its port
    parseOk(wrap("<remote><legacy><enabled>no</enabled><port>1515</port></legacy></remote>"));
    parseOk(wrap("<auth><disabled>yes</disabled><port>1517</port></auth>"));
}

TEST(Semantics, AuthPortIsReservedOnlyWhileAuthdBindsIt)
{
    // authd binds auth.port only for legacy enrollment, which follows remote.legacy.enabled when unset.
    parseOk(wrap("<auth><port>1517</port></auth>")); // no <legacy> block: legacy enrollment is off
    parseOk(wrap("<remote><legacy><enabled>no</enabled></legacy></remote><auth><port>1517</port></auth>"));
    EXPECT_EQ(
        parseKo(wrap("<remote><legacy><port>1514</port></legacy></remote><auth><port>1517</port></auth>")).pointer,
        "/auth/port")
        << "legacy enabled: legacy enrollment follows it";
    EXPECT_EQ(parseKo(wrap("<auth><legacy_enrollment>yes</legacy_enrollment><port>1517</port></auth>")).pointer,
              "/auth/port")
        << "an explicit legacy_enrollment wins over the absent <legacy> block";
    parseOk(wrap("<remote><legacy><port>1514</port></legacy></remote>"
                 "<auth><legacy_enrollment>no</legacy_enrollment><port>1517</port></auth>"));
    parseOk(wrap("<remote><legacy><port>1514</port></legacy></remote>"
                 "<auth><remote_enrollment>no</remote_enrollment><port>1517</port></auth>"));
    parseOk(wrap("<auth><disabled>yes</disabled><legacy_enrollment>yes</legacy_enrollment><port>1517</port></auth>"));
}

TEST(Semantics, CheckFilesResolvesRelativeToHome)
{
    const auto dir = std::filesystem::temp_directory_path() / "manager_config_utest_home";
    std::filesystem::create_directories(dir / "etc" / "certs");
    for (const char* name : {"remoted.pem", "remoted-key.pem", "root-ca.pem"})
    {
        std::ofstream(dir / "etc" / "certs" / name) << "x";
    }
    manager_config::LoadOptions options;
    options.home = dir;
    auto ok = manager_config::Document::parse(wrap(certificates("etc/certs")), options);
    EXPECT_TRUE(std::holds_alternative<manager_config::Document>(ok)) << std::get<manager_config::Error>(ok).what();
    auto ko = manager_config::Document::parse(wrap(certificates("etc/certs", "missing.pem")), options);
    ASSERT_TRUE(std::holds_alternative<manager_config::Error>(ko));
    EXPECT_EQ(std::get<manager_config::Error>(ko).pointer, "/remote/https/certificate");
    // An absolute path is used as is, never joined with the home.
    manager_config::LoadOptions elsewhere;
    elsewhere.home = dir / "elsewhere";
    auto absoluteOk = manager_config::Document::parse(wrap(certificates((dir / "etc" / "certs").string())), elsewhere);
    EXPECT_TRUE(std::holds_alternative<manager_config::Document>(absoluteOk))
        << std::get<manager_config::Error>(absoluteOk).what();
    // indexer.ssl.* is never checked: the installer does not create those files.
    auto indexerOk =
        manager_config::Document::parse(std::string("<wazuh_config><indexer><hosts><host>https://h:9200</host></hosts>"
                                                    "<ssl><certificate>etc/certs/missing.pem</certificate></ssl>"
                                                    "</indexer>") +
                                            certificates("etc/certs") + CLUSTER_SECTION + "</wazuh_config>",
                                        options);
    EXPECT_TRUE(std::holds_alternative<manager_config::Document>(indexerOk))
        << std::get<manager_config::Error>(indexerOk).what();
    std::filesystem::remove_all(dir);
}

TEST(Semantics, CaCertificateFileValidation)
{
    const auto dir = std::filesystem::temp_directory_path() / "manager_config_utest_ca_cert";
    std::filesystem::create_directories(dir / "etc" / "certs");
    for (const char* name : {"remoted.pem", "remoted-key.pem", "root-ca.pem"})
    {
        std::ofstream(dir / "etc" / "certs" / name) << "x";
    }
    manager_config::LoadOptions options;
    options.home = dir;
    auto ko =
        manager_config::Document::parse(wrap(certificates("etc/certs", "remoted.pem", "missing-ca.pem")), options);
    ASSERT_TRUE(std::holds_alternative<manager_config::Error>(ko));
    EXPECT_EQ(std::get<manager_config::Error>(ko).pointer, "/remote/https/ca_certificate");
    EXPECT_NE(std::get<manager_config::Error>(ko).message.find("file not found"), std::string::npos);
    std::filesystem::remove_all(dir);
}

// ---------------------------------------------------------------------------------------------------
// C API
// ---------------------------------------------------------------------------------------------------

TEST(CApi, LoadSectionDocumentValidateFree)
{
    const auto home = std::filesystem::temp_directory_path() / "manager_config_utest_capi";
    std::filesystem::create_directories(home / "etc" / "certs");
    for (const char* name : {"remoted.pem",
                             "remoted-key.pem",
                             "root-ca.pem",
                             "indexer-ca.pem",
                             "indexer-connector.pem",
                             "indexer-connector-key.pem"})
    {
        std::ofstream(home / "etc" / "certs" / name) << "x";
    }
    // The installer writes absolute /etc/wazuh-manager/certs/... paths; a copy with relative ones resolves
    // against `home` instead of the build host's real configuration directory.
    std::string generated = slurp(VECTORS / "valid" / "generated-manager.conf");
    const std::string absoluteCerts {"/etc/wazuh-manager/certs/"};
    for (auto at = generated.find(absoluteCerts); at != std::string::npos; at = generated.find(absoluteCerts, at))
    {
        generated.replace(at, absoluteCerts.size(), "etc/certs/");
    }
    const auto file = (home / "generated-manager.conf").string();
    std::ofstream(file) << generated;
    char err[512] = {0};
    mconf_t* conf = nullptr;
    // check_files == 0: the daemons load without requiring the certificate files (`-t` checks them)
    mconf_t* unchecked = nullptr;
    const auto emptyHome = std::filesystem::temp_directory_path() / "manager_config_utest_capi_empty";
    std::filesystem::create_directories(emptyHome);
    EXPECT_EQ(mconf_load(file.c_str(), emptyHome.c_str(), &unchecked, err, sizeof err), -1);
    EXPECT_EQ(unchecked, nullptr);
    ASSERT_EQ(mconf_load_ex(file.c_str(), emptyHome.c_str(), 0, &unchecked, err, sizeof err), 0) << err;
    mconf_free(unchecked);
    std::filesystem::remove_all(emptyHome);
    ASSERT_EQ(mconf_load(file.c_str(), home.c_str(), &conf, err, sizeof err), 0) << err;
    ASSERT_NE(conf, nullptr);
    char* remote = mconf_section_json(conf, "remote");
    ASSERT_NE(remote, nullptr);
    EXPECT_EQ(rapidjson::Pointer("/https/port").Get(json(remote))->GetInt(), 1517);
    std::free(remote);
    EXPECT_EQ(mconf_section_json(conf, "syscheck"), nullptr);
    char* whole = mconf_document_json(conf);
    ASSERT_NE(whole, nullptr);
    EXPECT_TRUE(json(whole).HasMember("cluster"));
    std::free(whole);
    mconf_free(conf);

    EXPECT_EQ(mconf_validate(file.c_str(), home.c_str(), err, sizeof err), 0) << err;
    EXPECT_EQ(
        mconf_validate((VECTORS / "invalid" / "true-false-boolean.conf").string().c_str(), nullptr, err, sizeof err),
        -1);
    EXPECT_STREQ(std::string(err).substr(0, 18).c_str(), "/auth/use_password");
    EXPECT_EQ(mconf_load("/nonexistent.conf", nullptr, &conf, err, sizeof err), -1);
    EXPECT_EQ(conf, nullptr);
    mconf_free(nullptr); // no-op
    std::filesystem::remove_all(home);
}

TEST(Schema, EmbeddedSchemaIsValidJsonWithSixtyNineLeaves)
{
    const auto schema = json(std::string {manager_config::schemaJson()});
    std::size_t leaves = 0;
    const std::function<void(const rapidjson::Value&)> walk = [&](const rapidjson::Value& node)
    {
        const auto props = node.FindMember("properties");
        if (props == node.MemberEnd())
        {
            return;
        }
        for (auto it = props->value.MemberBegin(); it != props->value.MemberEnd(); ++it)
        {
            if (it->value.HasMember("properties"))
            {
                walk(it->value);
            }
            else
            {
                ++leaves;
            }
        }
    };
    walk(schema);
    // Bump this deliberately, never to make the test pass: it is the guard that a schema option was
    // added or removed on purpose. Last changed by remote.https.groups (69 -> 70).
    EXPECT_EQ(leaves, 70u);
}
