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

} // namespace

// ---------------------------------------------------------------------------------------------------
// Load / defaults
// ---------------------------------------------------------------------------------------------------

TEST(Load, EffectiveDefaultsFromEmptyRoot)
{
    const auto doc = parseOk(slurp(VECTORS / "valid" / "empty-root.conf"));
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
    EXPECT_EQ(rapidjson::Pointer("/global/agents_disconnection_alert_time").Get(effective), nullptr);
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
    const auto doc = parseOk("<wazuh_config><remote><legacy><port>1514</port></legacy></remote></wazuh_config>");
    const auto remote = json(doc.sectionJson("remote"));
    EXPECT_TRUE(rapidjson::Pointer("/legacy/enabled").Get(remote)->GetBool());
    EXPECT_STREQ(rapidjson::Pointer("/legacy/protocol/0").Get(remote)->GetString(), "tcp");
}

TEST(Load, GeneratedManagerFileKeepsUserValuesAndFillsTheRest)
{
    const auto doc = parseOk(slurp(VECTORS / "valid" / "generated-manager.conf"));
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
    const auto doc = parseOk(slurp(VECTORS / "valid" / "durations-as-integers.conf"));
    const auto global = json(doc.sectionJson("global"));
    EXPECT_EQ(global["agents_disconnection_time"].GetInt(), 900);
    EXPECT_EQ(rapidjson::Pointer("/backup/global/interval").Get(json(doc.sectionJson("wdb")))->GetInt(), 3600);
}

TEST(Load, UnknownSectionQueryIsEmpty)
{
    const auto doc = parseOk("<wazuh_config/>");
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
    const auto doc = parseOk("<wazuh_config><auth><use_password>yes</use_password></auth></wazuh_config>");
    EXPECT_TRUE(json(doc.sectionJson("auth"))["use_password"].GetBool());
    const auto error = parseKo("<wazuh_config><auth><use_password>true</use_password></auth></wazuh_config>");
    EXPECT_EQ(error.pointer, "/auth/use_password");
    EXPECT_NE(error.message.find("type"), std::string::npos) << error.what();
    EXPECT_NE(error.message.find("booleans are yes/no"), std::string::npos) << error.what();
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
    const auto csv = parseOk("<wazuh_config><logging><log_format>plain, json</log_format></logging></wazuh_config>");
    const auto logging = json(csv.sectionJson("logging"));
    ASSERT_EQ(logging["log_format"].Size(), 2u);
    EXPECT_STREQ(logging["log_format"][1].GetString(), "json");
    const auto repeated = parseOk("<wazuh_config><logging><log_format>plain</log_format>"
                                  "<log_format>json</log_format></logging></wazuh_config>");
    EXPECT_EQ(json(repeated.sectionJson("logging"))["log_format"].Size(), 2u);
    const auto wrapper = parseOk("<wazuh_config><indexer><hosts><host>https://a:9200</host>"
                                 "<host>https://b:9200</host></hosts></indexer></wazuh_config>");
    const auto indexer = json(wrapper.sectionJson("indexer"));
    ASSERT_EQ(indexer["hosts"].Size(), 2u);
    EXPECT_STREQ(indexer["hosts"][1].GetString(), "https://b:9200");
}

TEST(Xml, AttributeFormsBecomeNestedObjects)
{
    const auto doc = parseOk("<wazuh_config><wdb><backup database=\"global\"><enabled>no</enabled>"
                             "<interval>1d</interval><max_files>3</max_files></backup></wdb>"
                             "<auth><force><disconnected_time enabled=\"yes\">1h</disconnected_time>"
                             "</force></auth></wazuh_config>");
    const auto wdb = json(doc.sectionJson("wdb"));
    EXPECT_FALSE(rapidjson::Pointer("/backup/global/enabled").Get(wdb)->GetBool());
    EXPECT_STREQ(rapidjson::Pointer("/backup/global/interval").Get(wdb)->GetString(), "1d");
    const auto auth = json(doc.sectionJson("auth"));
    EXPECT_TRUE(rapidjson::Pointer("/force/disconnected_time/enabled").Get(auth)->GetBool());
    EXPECT_STREQ(rapidjson::Pointer("/force/disconnected_time/value").Get(auth)->GetString(), "1h");
}

TEST(Xml, EntitiesAreDecodedAndEnumsNormalized)
{
    const auto doc = parseOk("<wazuh_config><cluster><name>a&amp;b</name>"
                             "<key>0123456789abcdef0123456789abcdef</key></cluster>"
                             "<remote><legacy><protocol>TCP,UDP</protocol></legacy>"
                             "<https><verification_mode>Full</verification_mode></https></remote></wazuh_config>");
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
    EXPECT_EQ(parseKo("<wazuh_config><remote><https><certificate>a.pem</certificate><key></key></https>"
                      "</remote></wazuh_config>")
                  .pointer,
              "/remote/https/key");
    EXPECT_EQ(parseKo("<wazuh_config><remote><legacy><port>1515</port></legacy></remote>"
                      "<auth><port>1515</port></auth></wazuh_config>")
                  .pointer,
              "/auth/port");
    EXPECT_EQ(parseKo("<wazuh_config><cluster><key>0123456789abcdef0123456789abcdef</key>"
                      "<port>1517</port></cluster></wazuh_config>")
                  .pointer,
              "/cluster/port")
        << "collides with remote.https.port default";
    EXPECT_EQ(parseKo("<wazuh_config><remote><https><global_prefix>/a/../b/</global_prefix></https>"
                      "</remote></wazuh_config>")
                  .pointer,
              "/remote/https/global_prefix");
    // a disabled listener does not reserve its port
    parseOk("<wazuh_config><remote><legacy><enabled>no</enabled><port>1515</port></legacy></remote></wazuh_config>");
    parseOk("<wazuh_config><auth><disabled>yes</disabled><port>1517</port></auth></wazuh_config>");
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
    auto ok = manager_config::Document::parse("<wazuh_config/>", options);
    EXPECT_TRUE(std::holds_alternative<manager_config::Document>(ok)) << std::get<manager_config::Error>(ok).what();
    auto ko = manager_config::Document::parse("<wazuh_config><remote><https>"
                                              "<certificate>etc/certs/missing.pem</certificate>"
                                              "<key>etc/certs/remoted-key.pem</key></https></remote></wazuh_config>",
                                              options);
    ASSERT_TRUE(std::holds_alternative<manager_config::Error>(ko));
    EXPECT_EQ(std::get<manager_config::Error>(ko).pointer, "/remote/https/certificate");
    // indexer.ssl.* is never checked: the installer does not create those files.
    auto indexerOk = manager_config::Document::parse("<wazuh_config><indexer><hosts><host>https://h:9200</host></hosts>"
                                                     "<ssl><certificate>etc/certs/missing.pem</certificate></ssl>"
                                                     "</indexer></wazuh_config>",
                                                     options);
    EXPECT_TRUE(std::holds_alternative<manager_config::Document>(indexerOk))
        << std::get<manager_config::Error>(indexerOk).what();
    std::filesystem::remove_all(dir);
}

// ---------------------------------------------------------------------------------------------------
// C API
// ---------------------------------------------------------------------------------------------------

TEST(CApi, LoadSectionDocumentValidateFree)
{
    const auto file = (VECTORS / "valid" / "generated-manager.conf").string();
    const auto home = std::filesystem::temp_directory_path() / "manager_config_utest_capi";
    std::filesystem::create_directories(home / "etc" / "certs");
    for (const char* name :
         {"remoted.pem", "remoted-key.pem", "root-ca.pem", "indexer-connector.pem", "indexer-connector-key.pem"})
    {
        std::ofstream(home / "etc" / "certs" / name) << "x";
    }
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
