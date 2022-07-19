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

#include "cveApiFetcher_test.hpp"
#include "cveApiFetcher.hpp"

void CveApiFetcherTest::SetUp() {};

void CveApiFetcherTest::TearDown() {};

TEST_F(CveApiFetcherTest, oneRemote_NoParameter)
{
    auto remote = R"({
                    "url": "https://access.redhat.com/hydra/rest/securitydata/cve.json",
                    "request": "api",
                    "type": "json"
                })"_json;

    CveApiFetcher apiFetcher;
    auto urls = apiFetcher.urlsFromRemote(remote);

    EXPECT_EQ("https://access.redhat.com/hydra/rest/securitydata/cve.json", urls[0]);
}

TEST_F(CveApiFetcherTest, oneRemote_MultipleFixedParameter)
{
    auto remote = R"({
                    "url": "https://access.redhat.com/labs/securitydataapi/cve.json?after={after}&per_page={per_page}",
                    "request": "api",
                    "type": "json",
                    "parameters": {
                        "after": {
                            "type": "fixed",
                            "description": "Date in ISO 8601 format (YYYY-MM-DD or YYYYMMDD) ",
                            "value": ["1999-01-01"]
                        },
                        "per_page": {
                            "type": "fixed",
                            "description": "Vulnerabilities per page",
                            "value": "1000"
                        }
                    }
                })"_json;

    CveApiFetcher apiFetcher;
    auto urls = apiFetcher.urlsFromRemote(remote);

    EXPECT_EQ(1u, urls.size());
    size_t i{0};
    EXPECT_EQ("https://access.redhat.com/labs/securitydataapi/cve.json?after=1999-01-01&per_page=1000", urls[i++]);
}

TEST_F(CveApiFetcherTest, oneRemote_OneIncrementalParameter)
{
    auto remote = R"({
                    "url": "https://access.redhat.com/labs/securitydataapi/cve.json?page={page}",
                    "request": "api",
                    "type": "json",
                    "parameters": {
                        "page": {
                            "type": "variable-incremental",
                            "classification": "range",
                            "value": {
                                "start": "1",
                                "end":   "5",
                                "step":  "1"
                            }
                        }
                    }
                })"_json;

    CveApiFetcher apiFetcher;
    auto urls = apiFetcher.urlsFromRemote(remote);

    size_t i{0};
    EXPECT_EQ(5u, urls.size());
    EXPECT_EQ("https://access.redhat.com/labs/securitydataapi/cve.json?page=1", urls[i++]);
    EXPECT_EQ("https://access.redhat.com/labs/securitydataapi/cve.json?page=2", urls[i++]);
    EXPECT_EQ("https://access.redhat.com/labs/securitydataapi/cve.json?page=3", urls[i++]);
    EXPECT_EQ("https://access.redhat.com/labs/securitydataapi/cve.json?page=4", urls[i++]);
    EXPECT_EQ("https://access.redhat.com/labs/securitydataapi/cve.json?page=5", urls[i++]);
}