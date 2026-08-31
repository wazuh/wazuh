/*
 * Copyright (C) 2015, Wazuh Inc.
 * This program is free software; you can redistribute it and/or modify it under the terms of GPLv2.
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

#include "manager_config/manager_config.hpp"
#include "manager_config/manager_config_c.h"
#include "yamlToJson.hpp"

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

    manager_config::Document parseOk(const std::string& yaml)
    {
        auto result = manager_config::Document::parse(yaml, noFiles());
        if (auto* error = std::get_if<manager_config::Error>(&result))
        {
            ADD_FAILURE() << "unexpected error: " << error->what();
        }
        return std::move(std::get<manager_config::Document>(result));
    }

    manager_config::Error parseKo(const std::string& yaml)
    {
        auto result = manager_config::Document::parse(yaml, noFiles());
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

} // namespace

// ---------------------------------------------------------------------------------------------------
// Load / defaults
// ---------------------------------------------------------------------------------------------------

TEST(Load, EffectiveDefaultsFromEmptyFile)
{
    const auto doc = parseOk(slurp(VECTORS / "valid" / "empty.yml"));
    const auto effective = json(doc.documentJson());
    for (const char* section : {"global",
                                "logging",
                                "remote",
                                "auth",
                                "wdb",
                                "vulnerability-detection",
                                "indexer",
                                "agent-upgrade",
                                "task-manager",
                                "cluster"})
    {
        EXPECT_TRUE(effective.HasMember(section)) << section;
    }
    EXPECT_STREQ(rapidjson::Pointer("/global/agents_disconnection_time").Get(effective)->GetString(), "15m");
    EXPECT_EQ(rapidjson::Pointer("/global/agents_disconnection_alert_time").Get(effective)->GetInt(), 0);
    EXPECT_STREQ(rapidjson::Pointer("/logging/log_format/0").Get(effective)->GetString(), "plain");
    // absent legacy block = disabled listener, but every option still has a value
    EXPECT_FALSE(rapidjson::Pointer("/remote/legacy/enabled").Get(effective)->GetBool());
    EXPECT_EQ(rapidjson::Pointer("/remote/legacy/port").Get(effective)->GetInt(), 1514);
    EXPECT_EQ(rapidjson::Pointer("/remote/https/port").Get(effective)->GetInt(), 1517);
    EXPECT_STREQ(rapidjson::Pointer("/remote/https/global_prefix").Get(effective)->GetString(), "/wazuh-manager/");
    EXPECT_EQ(rapidjson::Pointer("/remote/https/verification_mode").Get(effective), nullptr) << "no default: absent";
    EXPECT_EQ(rapidjson::Pointer("/auth/port").Get(effective)->GetInt(), 1515);
    EXPECT_TRUE(rapidjson::Pointer("/auth/force/disconnected_time/enabled").Get(effective)->GetBool());
    EXPECT_STREQ(rapidjson::Pointer("/wdb/backup/global/interval").Get(effective)->GetString(), "1d");
    EXPECT_EQ(rapidjson::Pointer("/vulnerability-detection/pageSize").Get(effective)->GetInt(), 100);
    EXPECT_EQ(rapidjson::Pointer("/indexer/hosts").Get(effective)->Size(), 0u) << "absent indexer: empty hosts";
    EXPECT_EQ(rapidjson::Pointer("/agent-upgrade/wpk_repository").Get(effective), nullptr)
        << "no default: the module picks the repository by target agent version";
    EXPECT_TRUE(rapidjson::Pointer("/agent-upgrade/enabled").Get(effective)->GetBool());
    EXPECT_EQ(rapidjson::Pointer("/task-manager/task_ttl").Get(effective)->GetInt(), 3600);
    EXPECT_STREQ(rapidjson::Pointer("/cluster/node_type").Get(effective)->GetString(), "master");
    EXPECT_EQ(rapidjson::Pointer("/cluster/nodes").Get(effective)->Size(), 1u);
}

TEST(Load, PresentLegacyBlockIsEnabledByDefault)
{
    const auto doc = parseOk("remote:\n  legacy:\n    port: 1514\n");
    const auto remote = json(doc.sectionJson("remote"));
    EXPECT_TRUE(rapidjson::Pointer("/legacy/enabled").Get(remote)->GetBool());
    EXPECT_STREQ(rapidjson::Pointer("/legacy/protocol/0").Get(remote)->GetString(), "tcp");
}

TEST(Load, GeneratedManagerFileKeepsUserValuesAndFillsTheRest)
{
    const auto doc = parseOk(slurp(VECTORS / "valid" / "generated-manager.yml"));
    const auto remote = json(doc.sectionJson("remote"));
    EXPECT_TRUE(rapidjson::Pointer("/legacy/enabled").Get(remote)->GetBool());
    EXPECT_EQ(rapidjson::Pointer("/legacy/queue_size").Get(remote)->GetInt(), 131072) << "filled default";
    EXPECT_STREQ(rapidjson::Pointer("/https/certificate").Get(remote)->GetString(), "etc/certs/remoted.pem");
    EXPECT_EQ(remote["https"].MemberCount(), 6u)
        << "port, bind_addr, global_prefix, certificate, key, ca (the three no-default options stay absent)";
    const auto auth = json(doc.sectionJson("auth"));
    EXPECT_TRUE(auth["purge"].GetBool());
    EXPECT_TRUE(auth["use_password"].GetBool());
    EXPECT_EQ(auth.MemberCount(), 15u) << "13 leaves + force + agents objects (18 inventory options)";
    const auto indexer = json(doc.sectionJson("indexer"));
    EXPECT_STREQ(rapidjson::Pointer("/hosts/0").Get(indexer)->GetString(), "https://127.0.0.1:9200");
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
    const auto doc = parseOk(slurp(VECTORS / "valid" / "durations-as-integers.yml"));
    const auto global = json(doc.sectionJson("global"));
    EXPECT_EQ(global["agents_disconnection_time"].GetInt(), 900);
    EXPECT_EQ(rapidjson::Pointer("/backup/global/interval").Get(json(doc.sectionJson("wdb")))->GetInt(), 3600);
}

TEST(Load, UnknownSectionQueryIsEmpty)
{
    const auto doc = parseOk("");
    EXPECT_TRUE(doc.sectionJson("syscheck").empty());
    EXPECT_FALSE(doc.hasSection("wodle"));
    EXPECT_TRUE(doc.hasSection("cluster"));
}

TEST(Load, MissingFileIsAnError)
{
    auto error = manager_config::validateFile(VECTORS / "does-not-exist.yml", noFiles());
    ASSERT_TRUE(error.has_value());
    EXPECT_NE(error->message.find("not found"), std::string::npos);
}

// ---------------------------------------------------------------------------------------------------
// Schema and YAML-level rejections, driven by the shared vectors
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
        if (keyword == "yaml")
        {
            EXPECT_TRUE(error.pointer.empty()) << name;
        }
        else if (keyword != "semantics")
        {
            EXPECT_NE(error.message.find(keyword), std::string::npos) << name << ": " << error.what();
        }
    }
    EXPECT_GE(vectors, 19u);
}

TEST(Schema, RejectsYesNoBooleanWithTypeKeyword)
{
    const auto error = parseKo("auth:\n  use_password: yes\n");
    EXPECT_EQ(error.pointer, "/auth/use_password");
    EXPECT_NE(error.message.find("type"), std::string::npos) << error.what();
}

TEST(Schema, RejectsUnknownKeyPointingAtTheKey)
{
    EXPECT_EQ(parseKo("remote:\n  https:\n    foo: 1\n").pointer, "/remote/https/foo");
    EXPECT_EQ(parseKo("syscheck: {}\n").pointer, "/syscheck");
}

TEST(Yaml, RejectsMultiDocAnchorsTagsAndNonMappingRoot)
{
    EXPECT_NE(parseKo("a: 1\n---\nb: 2\n").message.find("one YAML document"), std::string::npos);
    EXPECT_NE(parseKo("global: &g {}\nwdb: *g\n").message.find("anchors"), std::string::npos);
    EXPECT_NE(parseKo("auth:\n  port: !!str 1515\n").message.find("tags"), std::string::npos);
    EXPECT_EQ(parseKo("- a\n- b\n").pointer, "") << "non-mapping root: rejected by the schema (type)";
    EXPECT_NE(parseKo("auth:\n  port: 1515\n  port: 1516\n").message.find("duplicate"), std::string::npos);
}

TEST(Yaml, RejectsOversizeAndDepth)
{
    std::string big(manager_config::detail::MAX_YAML_BYTES + 1, '#');
    EXPECT_NE(parseKo(big).message.find("larger than"), std::string::npos);
    std::string deep;
    for (int i = 0; i < manager_config::detail::MAX_YAML_DEPTH + 1; ++i)
    {
        deep += std::string(static_cast<std::size_t>(i) * 2, ' ') + "k" + std::to_string(i) + ":\n";
    }
    deep += std::string(static_cast<std::size_t>(manager_config::detail::MAX_YAML_DEPTH + 1) * 2, ' ') + "v: 1\n";
    EXPECT_NE(parseKo(deep).message.find("deeper"), std::string::npos);
}

// ---------------------------------------------------------------------------------------------------
// Semantics
// ---------------------------------------------------------------------------------------------------

TEST(Semantics, CertificateWithoutKeyAndPortCollisionsAndDotSegments)
{
    EXPECT_EQ(parseKo("remote:\n  https:\n    certificate: a.pem\n    key: \"\"\n").pointer, "/remote/https/key");
    EXPECT_EQ(parseKo("remote:\n  legacy:\n    port: 1515\nauth:\n  port: 1515\n").pointer, "/auth/port");
    EXPECT_EQ(parseKo("cluster:\n  key: 0123456789abcdef0123456789abcdef\n  port: 1517\n").pointer, "/cluster/port")
        << "collides with remote.https.port default";
    EXPECT_EQ(parseKo("remote:\n  https:\n    global_prefix: /a/../b/\n").pointer, "/remote/https/global_prefix");
    // a disabled listener does not reserve its port
    parseOk("remote:\n  legacy:\n    enabled: false\n    port: 1515\n");
    parseOk("auth:\n  disabled: true\n  port: 1517\n");
}

TEST(Semantics, CheckFilesResolvesRelativeToHome)
{
    const auto dir = std::filesystem::temp_directory_path() / "manager_config_utest_home";
    std::filesystem::create_directories(dir / "etc" / "certs");
    for (const char* name : {"remoted.pem", "remoted-key.pem"})
    {
        std::ofstream(dir / "etc" / "certs" / name) << "x";
    }
    manager_config::LoadOptions options;
    options.home = dir;
    auto ok = manager_config::Document::parse("", options);
    EXPECT_TRUE(std::holds_alternative<manager_config::Document>(ok)) << std::get<manager_config::Error>(ok).what();
    auto ko = manager_config::Document::parse(
        "remote:\n  https:\n    certificate: etc/certs/missing.pem\n    key: etc/certs/remoted-key.pem\n", options);
    ASSERT_TRUE(std::holds_alternative<manager_config::Error>(ko));
    EXPECT_EQ(std::get<manager_config::Error>(ko).pointer, "/remote/https/certificate");
    // indexer.ssl.* is never checked: the installer does not create those files (P60).
    auto indexerOk = manager_config::Document::parse(
        "indexer:\n  hosts: [\"https://h:9200\"]\n  ssl:\n    certificate: etc/certs/missing.pem\n", options);
    EXPECT_TRUE(std::holds_alternative<manager_config::Document>(indexerOk))
        << std::get<manager_config::Error>(indexerOk).what();
    std::filesystem::remove_all(dir);
}

// ---------------------------------------------------------------------------------------------------
// C API
// ---------------------------------------------------------------------------------------------------

TEST(CApi, LoadSectionDocumentValidateFree)
{
    const auto file = (VECTORS / "valid" / "generated-manager.yml").string();
    const auto home = std::filesystem::temp_directory_path() / "manager_config_utest_capi";
    std::filesystem::create_directories(home / "etc" / "certs");
    for (const char* name :
         {"remoted.pem", "remoted-key.pem", "root-ca.pem", "indexer-connector.pem", "indexer-connector-key.pem"})
    {
        std::ofstream(home / "etc" / "certs" / name) << "x";
    }
    char err[512] = {0};
    mconf_t* conf = nullptr;
    // check_files == 0: the daemons load without requiring the certificate files (P44: `-t` checks them)
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
    EXPECT_EQ(mconf_validate((VECTORS / "invalid" / "yes-no-boolean.yml").string().c_str(), nullptr, err, sizeof err),
              -1);
    EXPECT_STREQ(std::string(err).substr(0, 18).c_str(), "/auth/use_password");
    EXPECT_EQ(mconf_load("/nonexistent.yml", nullptr, &conf, err, sizeof err), -1);
    EXPECT_EQ(conf, nullptr);
    mconf_free(nullptr); // no-op
    std::filesystem::remove_all(home);
}

TEST(Schema, EmbeddedSchemaIsValidJsonWithSixtySixLeaves)
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
    EXPECT_EQ(leaves, 66u);
}
