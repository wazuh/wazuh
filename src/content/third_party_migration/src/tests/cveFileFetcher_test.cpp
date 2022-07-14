/*
 * Wazuh app - Command line helper
 * Copyright (C) 2015, Wazuh Inc.
 * July 14, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "cveFileFetcher_test.hpp"
#include "cveFileFetcher.hpp"

void CveFileFetcherTest::SetUp() {};

void CveFileFetcherTest::TearDown() {};

TEST_F(CveFileFetcherTest, dummyTest)
{
    CveFileFetcher fileFetcher;
    auto urls = fileFetcher.urlsFromRemote(nullptr);

    EXPECT_EQ(0u, urls.size());
}

TEST_F(CveFileFetcherTest, oneRemote_RequestTypeNotFile)
{
    auto remote = R"(
                    {
                     "url": "https://alas.aws.amazon.com/alas.rss",
                     "request": "api",
                     "type": "xml"
                    })"_json;

    CveFileFetcher fileFetcher;
    EXPECT_THROW(fileFetcher.urlsFromRemote(remote), std::runtime_error);
}


TEST_F(CveFileFetcherTest, oneRemote_FixedUrl)
{
    auto remote = R"(
                    {
                     "url": "https://alas.aws.amazon.com/alas.rss",
                     "request": "file",
                     "type": "xml"
                    })"_json;

    CveFileFetcher fileFetcher;
    auto urls = fileFetcher.urlsFromRemote(remote);

    EXPECT_EQ("https://alas.aws.amazon.com/alas.rss", urls[0]);
}

TEST_F(CveFileFetcherTest, oneRemote_OneFixedParameter)
{
    auto remote = R"(
                    {
                    "url": "https://alas.aws.amazon.com/AL{version}/alas.rss",
                    "request": "file",
                    "type": "xml",
                    "parameters": {
                        "version": {
                            "type": "fixed",
                            "description": "Amazon Linux version",
                            "value": [
                                    "2",
                                    "2022"
                                    ]
                            }
                        }
                    })"_json;

    CveFileFetcher fileFetcher;
    auto urls = fileFetcher.urlsFromRemote(remote);

    EXPECT_EQ(2u, urls.size());
    EXPECT_EQ("https://alas.aws.amazon.com/AL2/alas.rss", urls[0]);
    EXPECT_EQ("https://alas.aws.amazon.com/AL2022/alas.rss", urls[1]);
}

TEST_F(CveFileFetcherTest, oneRemote_OneRepeatedPlaceHolder)
{
    auto remote = R"({
                    "url": "https://www.redhat.com/security/data/oval/v2/RHEL{version}/rhel-{version}-including-unpatched.oval.xml.bz2",
                    "request": "file",
                    "type": "xml",
                    "compressed": "bzip2",
                    "parameters": {
                        "version": {
                            "type": "fixed",
                            "description": "RedHat version number",
                            "value": [
                                    "6",
                                    "7",
                                    "8",
                                    "9"
                                    ]
                            }
                        }
                    }
                    )"_json;

    CveFileFetcher fileFetcher;
    auto urls = fileFetcher.urlsFromRemote(remote);

    EXPECT_EQ(4u, urls.size());
    EXPECT_EQ("https://www.redhat.com/security/data/oval/v2/RHEL6/rhel-6-including-unpatched.oval.xml.bz2", urls[0]);
    EXPECT_EQ("https://www.redhat.com/security/data/oval/v2/RHEL7/rhel-7-including-unpatched.oval.xml.bz2", urls[1]);
    EXPECT_EQ("https://www.redhat.com/security/data/oval/v2/RHEL8/rhel-8-including-unpatched.oval.xml.bz2", urls[2]);
    EXPECT_EQ("https://www.redhat.com/security/data/oval/v2/RHEL9/rhel-9-including-unpatched.oval.xml.bz2", urls[3]);
}

TEST_F(CveFileFetcherTest, oneRemote_TwoFixedPlaceHolders)
{
    auto remote = R"({
                    "url": "https://ftp.suse.com/pub/projects/security/oval/suse.linux.enterprise.{type}.{version}.xml",
                    "request": "file",
                    "type": "xml",
                    "parameters": {
                        "version": {
                            "type": "fixed",
                            "description": "SLE version number",
                            "value": [
                                "11",
                                "12",
                                "15"
                                ]
                            },
                        "type": {
                            "type": "fixed",
                            "description": "SLE version type",
                            "value": [
                                "desktop",
                                "server"
                                ]
                            }
                        }
                    })"_json;

    CveFileFetcher fileFetcher;
    auto urls = fileFetcher.urlsFromRemote(remote);

    EXPECT_EQ(6u, urls.size());
    EXPECT_EQ("https://ftp.suse.com/pub/projects/security/oval/suse.linux.enterprise.desktop.11.xml", urls[0]);
    EXPECT_EQ("https://ftp.suse.com/pub/projects/security/oval/suse.linux.enterprise.desktop.12.xml", urls[1]);
    EXPECT_EQ("https://ftp.suse.com/pub/projects/security/oval/suse.linux.enterprise.desktop.15.xml", urls[2]);
    EXPECT_EQ("https://ftp.suse.com/pub/projects/security/oval/suse.linux.enterprise.server.11.xml", urls[3]);
    EXPECT_EQ("https://ftp.suse.com/pub/projects/security/oval/suse.linux.enterprise.server.12.xml", urls[4]);
    EXPECT_EQ("https://ftp.suse.com/pub/projects/security/oval/suse.linux.enterprise.server.15.xml", urls[5]);


}

TEST_F(CveFileFetcherTest, oneRemote_MultipleFixedPlaceHolders)
{
    auto remote = R"({
                    "url": "https://ftp.suse.com/{first}/{second}/{third}-{fourth}.xml",
                    "request": "file",
                    "type": "xml",
                    "parameters": {
                        "first": {
                            "type": "fixed",
                            "value": ["A","B","C"]
                            },
                        "second": {
                            "type": "fixed",
                            "description": "second",
                            "value": ["001","002"]
                            },
                        "fourth": {
                            "type": "fixed",
                            "description": "fourth",
                            "value": ["ZZZ","YYY"]
                            },
                        "third": {
                            "type": "fixed",
                            "description": "third",
                            "value": ["333"]
                            }
                        }
                    })"_json;

    CveFileFetcher fileFetcher;
    auto urls = fileFetcher.urlsFromRemote(remote);

    EXPECT_EQ(12u, urls.size());
    size_t i{0};
    EXPECT_EQ("https://ftp.suse.com/A/001/333-ZZZ.xml", urls[i++]);
    EXPECT_EQ("https://ftp.suse.com/A/001/333-YYY.xml", urls[i++]);
    EXPECT_EQ("https://ftp.suse.com/A/002/333-ZZZ.xml", urls[i++]);
    EXPECT_EQ("https://ftp.suse.com/A/002/333-YYY.xml", urls[i++]);
    EXPECT_EQ("https://ftp.suse.com/B/001/333-ZZZ.xml", urls[i++]);
    EXPECT_EQ("https://ftp.suse.com/B/001/333-YYY.xml", urls[i++]);
    EXPECT_EQ("https://ftp.suse.com/B/002/333-ZZZ.xml", urls[i++]);
    EXPECT_EQ("https://ftp.suse.com/B/002/333-YYY.xml", urls[i++]);
    EXPECT_EQ("https://ftp.suse.com/C/001/333-ZZZ.xml", urls[i++]);
    EXPECT_EQ("https://ftp.suse.com/C/001/333-YYY.xml", urls[i++]);
    EXPECT_EQ("https://ftp.suse.com/C/002/333-ZZZ.xml", urls[i++]);
    EXPECT_EQ("https://ftp.suse.com/C/002/333-YYY.xml", urls[i++]);
}