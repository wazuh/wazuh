/*
 * Wazuh SyscollectorImp
 * Copyright (C) 2015, Wazuh Inc.
 * August 1, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "syscollectorFb_test.h"

constexpr auto SYNC_HMSG_TEST_PATH {"sync_hmsg.mom"};
constexpr auto SYNC_PMSG_TEST_PATH {"sync_pmsg.mom"};

constexpr auto COMPONENT {"syscollector"};
constexpr auto TYPE {"state"};

const std::string package_fbs {SCHEMA_ROOT_PATH "package_synchronization.fbs"};

const std::string hotfix_fbs {SCHEMA_ROOT_PATH "hotfix_synchronization.fbs"};

void SyscollectorFbTest::SetUp() {};

void SyscollectorFbTest::TearDown() {};


TEST(SyscollectorFbTest, packageJSONParserUnix)
{

    const std::string alert_json =
        "{\n  component: \"syscollector_packages\",\n  data: {\n    attributes: {\n      architecture: \"amd64\",\n      checksum: \"409378153d05da4d49900316be982e575cb2586b\",\n      description: \"GNU C++ compiler for MinGW-w64 targeting Win64\",\n      format: \"deb\",\n      groups: \"devel\",\n      item_id: \"65a25b9b9fe7cb173aa5cc36dc437d9875af8a8e\",\n      name: \"g++-mingw-w64-x86-64\",\n      priority: \"optional\",\n      scan_time: \"2023/07/25 00:22:55\",\n      size: 155993,\n      source: \"gcc-mingw-w64 (22~exp1ubuntu4)\",\n      vendor: \"Stephen Kitt <skitt@debian.org>\",\n      version: \"9.3.0-7ubuntu1+22~exp1ubuntu4\"\n    },\n    index: \"65a25b9b9fe7cb173aa5cc36dc437d9875af8a8e\",\n    timestamp: \"\"\n  },\n  type: \"state\"\n}\n";

    flatbuffers::Parser parser;
    std::string schemaFile;

    bool loadSuccess = flatbuffers::LoadFile(package_fbs.c_str(), false, &schemaFile);

    EXPECT_TRUE(loadSuccess);

    bool parseSuccess = parser.Parse(schemaFile.c_str()) && parser.Parse(alert_json.c_str());

    EXPECT_TRUE(parseSuccess);

    std::string json_gen;

    bool genSuccess = GenText(parser, parser.builder_.GetBufferPointer(), &json_gen);

    EXPECT_FALSE(genSuccess);

    EXPECT_STREQ(alert_json.c_str(), json_gen.c_str());

}

TEST(SyscollectorFbTest, hotfixJSONParser)
{
    const std::string alert_json =
        "{\n  component: \"syscollector_hotfixes\",\n  data: {\n    attributes: {\n      checksum: \"5cfcee837ce896ef9229da1064b2844439ff3cc6\",\n      hotfix: \"KB5026037\",\n      scan_time: \"2023/08/04 09:55:48\"\n    },\n    index: \"KB5026037\",\n    timestamp: \"\"\n  },\n  type: \"state\"\n}\n";

    flatbuffers::Parser parser;
    std::string schemaFile;

    bool loadSuccess = flatbuffers::LoadFile(hotfix_fbs.c_str(), false, &schemaFile);

    EXPECT_TRUE(loadSuccess);

    bool parseSuccess = parser.Parse(schemaFile.c_str()) && parser.Parse(alert_json.c_str());

    EXPECT_TRUE(parseSuccess);

    std::string json_gen;

    bool genSuccess = GenText(parser, parser.builder_.GetBufferPointer(), &json_gen);

    EXPECT_FALSE(genSuccess);

    EXPECT_STREQ(alert_json.c_str(), json_gen.c_str());

}

TEST(SyscollectorFbTest, packageJSONParserWin)
{
    const std::string alert_json =
        "{\n  component: \"syscollector_packages\",\n  data: {\n    attributes: {\n      architecture: \"\",\n      checksum: \"9141d4744f95aad5db1cf8cf17c33c2f7dffed40\",\n      format: \"win\",\n      install_time: \"20230804\",\n      item_id: \"e8cc756531b3adaae0e8a51c6800a681f4e903aa\",\n      name: \"Microsoft Edge WebView2 Runtime\",\n      location: \"C:Windows \",\n      scan_time: \"2023/07/25 00:22:55\",\n      vendor: \"Microsoft Corporation\",\n      version: \"115.0.1901.188\"\n    },\n    index: \"e8cc756531b3adaae0e8a51c6800a681f4e903aa\",\n    timestamp: \"\"\n  },\n  type: \"state\"\n}\n";

    flatbuffers::Parser parser;
    std::string schemaFile;

    bool loadSuccess = flatbuffers::LoadFile(package_fbs.c_str(), false, &schemaFile);

    EXPECT_TRUE(loadSuccess);

    bool parseSuccess = parser.Parse(schemaFile.c_str()) && parser.Parse(alert_json.c_str());

    EXPECT_TRUE(parseSuccess);

    std::string json_gen;

    bool genSuccess = GenText(parser, parser.builder_.GetBufferPointer(), &json_gen);

    EXPECT_FALSE(genSuccess);

    EXPECT_STREQ(alert_json.c_str(), json_gen.c_str());

}

TEST(SyscollectorFbTest, createBinaryPackageUnix)
{
    flatbuffers::FlatBufferBuilder builder;
    std::ifstream infile;

    auto component = builder.CreateString(COMPONENT);
    auto type = builder.CreateString(TYPE);

    auto architecture = builder.CreateString("x86");
    auto checksum = builder.CreateString("md5sha1md5sha1");
    auto description = builder.CreateString("Nice");
    auto format = builder.CreateString("UTF-8");
    auto install_time = builder.CreateString(nullptr, 0);
    auto groups = builder.CreateString("wazuh");
    auto item_id = builder.CreateString("00");
    auto multiarch = builder.CreateString("yes");
    auto name = builder.CreateString("NicePackage");
    auto location = builder.CreateString("\\home");
    auto priority = builder.CreateString("01");
    auto scan_time = builder.CreateString("00/00/0000T00:00:00.000");
    auto size_attr = 1;
    auto source = builder.CreateString("wazuh");
    auto vendor = builder.CreateString("wazuh");
    auto version = builder.CreateString("v1");

    auto attributes = CreatePackageAttribute(
                          builder,
                          architecture,
                          checksum,
                          description,
                          format,
                          install_time,
                          groups,
                          item_id,
                          multiarch,
                          name,
                          location,
                          priority,
                          scan_time,
                          size_attr,
                          source,
                          vendor,
                          version);

    auto index = builder.CreateString("00");
    auto timestamp = builder.CreateString("00/00/0000T00:00:00.000");

    auto packageData = CreatePackageData(builder, attributes, index, timestamp);

    auto sync_msg_w = CreateSyncMsgPkg(builder, component, packageData, type);

    builder.Finish(sync_msg_w);

    uint8_t* buf = builder.GetBufferPointer();
    int size = builder.GetSize();

    std::ofstream ofile(SYNC_PMSG_TEST_PATH, std::ios::binary);
    ofile.write((char*)buf, size);
    ofile.close();

    infile.open(SYNC_PMSG_TEST_PATH, std::ios::binary | std::ios::in);
    infile.seekg(0, std::ios::end);
    int length = infile.tellg();
    infile.seekg(0, std::ios::beg);
    char* raw_data = new char[length];
    infile.read(raw_data, length);
    infile.close();

    auto sync_msg_r = GetSyncMsgPkg(raw_data);

    EXPECT_STREQ(sync_msg_r->component()->c_str(), COMPONENT);
    EXPECT_STREQ(sync_msg_r->type()->c_str(), TYPE);
    EXPECT_STREQ(sync_msg_r->data()->attributes()->architecture()->c_str(), "x86");
    EXPECT_STREQ(sync_msg_r->data()->attributes()->checksum()->c_str(), "md5sha1md5sha1");
    EXPECT_STREQ(sync_msg_r->data()->attributes()->description()->c_str(), "Nice");
    EXPECT_STREQ(sync_msg_r->data()->attributes()->format()->c_str(), "UTF-8");
    EXPECT_STREQ(sync_msg_r->data()->attributes()->install_time()->c_str(), "");
    EXPECT_STREQ(sync_msg_r->data()->attributes()->groups()->c_str(), "wazuh");
    EXPECT_STREQ(sync_msg_r->data()->attributes()->item_id()->c_str(), "00");
    EXPECT_STREQ(sync_msg_r->data()->attributes()->multiarch()->c_str(), "yes");
    EXPECT_STREQ(sync_msg_r->data()->attributes()->name()->c_str(), "NicePackage");
    EXPECT_STREQ(sync_msg_r->data()->attributes()->location()->c_str(), "\\home");
    EXPECT_STREQ(sync_msg_r->data()->attributes()->priority()->c_str(), "01");
    EXPECT_STREQ(sync_msg_r->data()->attributes()->scan_time()->c_str(), "00/00/0000T00:00:00.000");
    EXPECT_EQ(sync_msg_r->data()->attributes()->size(), 1);
    EXPECT_STREQ(sync_msg_r->data()->attributes()->source()->c_str(), "wazuh");
    EXPECT_STREQ(sync_msg_r->data()->attributes()->vendor()->c_str(), "wazuh");
    EXPECT_STREQ(sync_msg_r->data()->attributes()->version()->c_str(), "v1");
    EXPECT_STREQ(sync_msg_r->data()->index()->c_str(), "00");
    EXPECT_STREQ(sync_msg_r->data()->timestamp()->c_str(), "00/00/0000T00:00:00.000");

    std::remove(SYNC_PMSG_TEST_PATH);
    delete []raw_data;
}

TEST(SyscollectorFbTest, createBinaryPackageWin)
{
    flatbuffers::FlatBufferBuilder builder;
    std::ifstream infile;

    auto component = builder.CreateString(COMPONENT);
    auto type = builder.CreateString(TYPE);

    auto architecture = builder.CreateString("x86");
    auto checksum = builder.CreateString("md5sha1md5sha1");
    auto description = builder.CreateString(nullptr, 0);
    auto format = builder.CreateString("UTF-8");
    auto install_time = builder.CreateString("00/00/0000T00:00:00.000");
    auto groups = builder.CreateString(nullptr, 0);
    auto item_id = builder.CreateString("00");
    auto multiarch = builder.CreateString(nullptr, 0);
    auto name = builder.CreateString("NicePackage");
    auto location = builder.CreateString("\\home");
    auto priority = builder.CreateString(nullptr, 0);
    auto scan_time = builder.CreateString("00/00/0000T00:00:00.000");
    auto size_attr = 0;
    auto source = builder.CreateString("wazuh");
    auto vendor = builder.CreateString("wazuh");
    auto version = builder.CreateString("v1");

    auto attributes = CreatePackageAttribute(
                          builder,
                          architecture,
                          checksum,
                          description,
                          format,
                          install_time,
                          groups,
                          item_id,
                          multiarch,
                          name,
                          location,
                          priority,
                          scan_time,
                          size_attr,
                          source,
                          vendor,
                          version);

    auto index = builder.CreateString("00");
    auto timestamp = builder.CreateString("00/00/0000T00:00:00.000");

    auto packageData = CreatePackageData(builder, attributes, index, timestamp);

    auto sync_msg_w = CreateSyncMsgPkg(builder, component, packageData, type);

    builder.Finish(sync_msg_w);

    uint8_t* buf = builder.GetBufferPointer();
    int size = builder.GetSize();

    std::ofstream ofile(SYNC_PMSG_TEST_PATH, std::ios::binary);
    ofile.write((char*)buf, size);
    ofile.close();


    infile.open(SYNC_PMSG_TEST_PATH, std::ios::binary | std::ios::in);
    infile.seekg(0, std::ios::end);
    int length = infile.tellg();
    infile.seekg(0, std::ios::beg);
    char* raw_data = new char[length];
    infile.read(raw_data, length);
    infile.close();

    auto sync_msg_r = GetSyncMsgPkg(raw_data);

    EXPECT_STREQ(sync_msg_r->component()->c_str(), COMPONENT);
    EXPECT_STREQ(sync_msg_r->type()->c_str(), TYPE);
    EXPECT_STREQ(sync_msg_r->data()->attributes()->architecture()->c_str(), "x86");
    EXPECT_STREQ(sync_msg_r->data()->attributes()->checksum()->c_str(), "md5sha1md5sha1");
    EXPECT_STREQ(sync_msg_r->data()->attributes()->description()->c_str(), "");
    EXPECT_STREQ(sync_msg_r->data()->attributes()->format()->c_str(), "UTF-8");
    EXPECT_STREQ(sync_msg_r->data()->attributes()->install_time()->c_str(), "00/00/0000T00:00:00.000");
    EXPECT_STREQ(sync_msg_r->data()->attributes()->groups()->c_str(), "");
    EXPECT_STREQ(sync_msg_r->data()->attributes()->item_id()->c_str(), "00");
    EXPECT_STREQ(sync_msg_r->data()->attributes()->multiarch()->c_str(), "");
    EXPECT_STREQ(sync_msg_r->data()->attributes()->name()->c_str(), "NicePackage");
    EXPECT_STREQ(sync_msg_r->data()->attributes()->location()->c_str(), "\\home");
    EXPECT_STREQ(sync_msg_r->data()->attributes()->priority()->c_str(), "");
    EXPECT_STREQ(sync_msg_r->data()->attributes()->scan_time()->c_str(), "00/00/0000T00:00:00.000");
    EXPECT_EQ(sync_msg_r->data()->attributes()->size(), 0);
    EXPECT_STREQ(sync_msg_r->data()->attributes()->source()->c_str(), "wazuh");
    EXPECT_STREQ(sync_msg_r->data()->attributes()->vendor()->c_str(), "wazuh");
    EXPECT_STREQ(sync_msg_r->data()->attributes()->version()->c_str(), "v1");
    EXPECT_STREQ(sync_msg_r->data()->index()->c_str(), "00");
    EXPECT_STREQ(sync_msg_r->data()->timestamp()->c_str(), "00/00/0000T00:00:00.000");

    std::remove(SYNC_PMSG_TEST_PATH);
    delete []raw_data;
}

TEST(SyscollectorFbTest, createBinaryHotfix)
{
    flatbuffers::FlatBufferBuilder builder;
    std::ifstream infile;


    auto component = builder.CreateString(COMPONENT);
    auto type = builder.CreateString(TYPE);

    auto checksum = builder.CreateString("md5sha1md5sha1");
    auto hotfix = builder.CreateString("KBXXXXX");
    auto scan_time = builder.CreateString("00");

    auto attributes = CreateHotfixAttribute(builder, checksum, hotfix, scan_time);

    auto index = builder.CreateString("00");
    auto timestamp = builder.CreateString("00/00/0000T00:00:00.000");

    auto data = CreateHotfixData(builder, attributes, index, timestamp);


    auto sync_msg_w = CreateSyncMsgHtx(builder, component, data, type);

    builder.Finish(sync_msg_w);

    uint8_t* buf = builder.GetBufferPointer();
    int size = builder.GetSize();

    std::ofstream ofile(SYNC_HMSG_TEST_PATH, std::ios::binary);
    ofile.write((char*)buf, size);
    ofile.close();

    infile.open(SYNC_HMSG_TEST_PATH, std::ios::binary | std::ios::in);
    infile.seekg(0, std::ios::end);
    int length = infile.tellg();
    infile.seekg(0, std::ios::beg);
    char* raw_data = new char[length];
    infile.read(raw_data, length);
    infile.close();

    auto sync_msg_r = GetSyncMsgHtx(raw_data);

    EXPECT_STREQ(sync_msg_r->component()->c_str(), COMPONENT);
    EXPECT_STREQ(sync_msg_r->type()->c_str(), TYPE);
    EXPECT_STREQ(sync_msg_r->data()->index()->c_str(), "00");
    EXPECT_STREQ(sync_msg_r->data()->timestamp()->c_str(), "00/00/0000T00:00:00.000");
    EXPECT_STREQ(sync_msg_r->data()->attributes()->checksum()->c_str(), "md5sha1md5sha1");
    EXPECT_STREQ(sync_msg_r->data()->attributes()->hotfix()->c_str(), "KBXXXXX");
    EXPECT_STREQ(sync_msg_r->data()->attributes()->scan_time()->c_str(), "00");

    std::remove(SYNC_HMSG_TEST_PATH);
    delete []raw_data;
}
