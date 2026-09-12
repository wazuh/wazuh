/*
 * Wazuh content manager - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "components/executionContext.hpp"
#include "gtest/gtest.h"
#include <stdexcept>

namespace
{

nlohmann::json cursorConfig()
{
    return nlohmann::json {{"consumerName", "Test Consumer"},
                           {"changeDetection", "cursor"},
                           {"indexer",
                            {{"index", "data-index"},
                             {"consumerStatusIndex", ".consumers"},
                             {"consumerStatusId", "consumer:1"}}}};
}

nlohmann::json hashConfig()
{
    return nlohmann::json {{"consumerName", "Test Consumer"},
                           {"changeDetection", "hash"},
                           {"indexer",
                            {{"index", "data-index"},
                             {"hashDocId", "manifest"},
                             {"hashPointers", nlohmann::json::array({"/hash"})},
                             {"dataQuery", {{"match_all", nlohmann::json::object()}}}}}};
}

} // namespace

TEST(ExecutionContextTest, AcceptsAValidCursorConfiguration)
{
    EXPECT_NO_THROW(ExecutionContext::validate(cursorConfig()));
}

TEST(ExecutionContextTest, AcceptsAValidHashConfiguration)
{
    EXPECT_NO_THROW(ExecutionContext::validate(hashConfig()));
}

TEST(ExecutionContextTest, RejectsAMissingConsumerName)
{
    auto config = cursorConfig();
    config.erase("consumerName");
    EXPECT_THROW(ExecutionContext::validate(config), std::invalid_argument);

    config["consumerName"] = "";
    EXPECT_THROW(ExecutionContext::validate(config), std::invalid_argument);
}

TEST(ExecutionContextTest, RejectsAnUnknownChangeDetection)
{
    auto config = cursorConfig();
    config["changeDetection"] = "magic";
    EXPECT_THROW(ExecutionContext::validate(config), std::invalid_argument);

    config.erase("changeDetection");
    EXPECT_THROW(ExecutionContext::validate(config), std::invalid_argument);
}

TEST(ExecutionContextTest, RejectsAMissingIndexerSection)
{
    auto config = cursorConfig();
    config.erase("indexer");
    EXPECT_THROW(ExecutionContext::validate(config), std::invalid_argument);
}

TEST(ExecutionContextTest, RejectsAnEmptyIndexList)
{
    auto config = cursorConfig();
    config["indexer"].erase("index");
    EXPECT_THROW(ExecutionContext::validate(config), std::invalid_argument);

    config["indexer"]["indices"] = nlohmann::json::array();
    EXPECT_THROW(ExecutionContext::validate(config), std::invalid_argument);
}

TEST(ExecutionContextTest, RejectsANonConcreteConsumerStatusIndex)
{
    // Both defences against consumer documents leaking into the content compare against the
    // `_index` metafield, which reports CONCRETE backing index names. A pattern or an alias would
    // simply never match, and the leak would be silent — so it is refused at registration.
    for (const auto* bad : {".consumers-*", ".consumers,.other", "-hidden"})
    {
        auto config = cursorConfig();
        config["indexer"]["consumerStatusIndex"] = bad;
        EXPECT_THROW(ExecutionContext::validate(config), std::invalid_argument) << bad;
    }
}

TEST(ExecutionContextTest, RejectsAConsumerIndexWithoutAnId)
{
    auto config = cursorConfig();
    config["indexer"].erase("consumerStatusId");
    EXPECT_THROW(ExecutionContext::validate(config), std::invalid_argument);
}

TEST(ExecutionContextTest, HashModeRequiresExactlyOneProbeShape)
{
    auto both = hashConfig();
    both["indexer"]["hashIndex"] = "policies";
    both["indexer"]["hashQuery"] = nlohmann::json::object();
    EXPECT_THROW(ExecutionContext::validate(both), std::invalid_argument);

    auto neither = hashConfig();
    neither["indexer"].erase("hashDocId");
    EXPECT_THROW(ExecutionContext::validate(neither), std::invalid_argument);
}

TEST(ExecutionContextTest, QueryProbeRequiresAQuery)
{
    auto config = hashConfig();
    config["indexer"].erase("hashDocId");
    config["indexer"]["hashIndex"] = "policies";
    EXPECT_THROW(ExecutionContext::validate(config), std::invalid_argument);

    config["indexer"]["hashQuery"] = nlohmann::json {{"match_all", nlohmann::json::object()}};
    EXPECT_NO_THROW(ExecutionContext::validate(config));
}

TEST(ExecutionContextTest, HashModeRequiresUsablePointersAndADataQuery)
{
    auto noPointers = hashConfig();
    noPointers["indexer"]["hashPointers"] = nlohmann::json::array();
    EXPECT_THROW(ExecutionContext::validate(noPointers), std::invalid_argument);

    auto badPointer = hashConfig();
    badPointer["indexer"]["hashPointers"] = nlohmann::json::array({"hash"});
    EXPECT_THROW(ExecutionContext::validate(badPointer), std::invalid_argument);

    auto noQuery = hashConfig();
    noQuery["indexer"].erase("dataQuery");
    EXPECT_THROW(ExecutionContext::validate(noQuery), std::invalid_argument);
}

TEST(ExecutionContextTest, RejectsZeroSlices)
{
    auto config = cursorConfig();
    config["indexer"]["numSlices"] = 0;
    EXPECT_THROW(ExecutionContext::validate(config), std::invalid_argument);
}

TEST(ExecutionContextTest, RejectsAMistypedSourceFilter)
{
    // The one that has to be caught here rather than anywhere else: the filter is read behind an
    // `is_object` test, so a mistyped one is silently ignored — and a vulnerability feed downloaded
    // without its `_source` filter still works, it is just several gigabytes instead of a few
    // hundred megabytes. Nothing downstream would ever report it.
    auto config = cursorConfig();
    config["indexer"]["sourceFilter"] = "excludes-everything";
    EXPECT_THROW(ExecutionContext::validate(config), std::invalid_argument);
}

TEST(ExecutionContextTest, RejectsMistypedQueryShapeKeys)
{
    const auto rejects = [](const std::string& key, const nlohmann::json& value)
    {
        auto config = cursorConfig();
        config["indexer"][key] = value;
        EXPECT_THROW(ExecutionContext::validate(config), std::invalid_argument)
            << "indexer." << key << " accepted a value of the wrong type";
    };

    // Every one of these is read later with json::value(key, default), which throws a type_error
    // naming nothing useful — at cycle time, on a topic that registered cleanly.
    rejects("pageSize", "100");
    rejects("numSlices", -1);
    rejects("keepAlive", 300);
    rejects("keepAlive", "");
    rejects("expandWildcards", "true");
    rejects("cursorField", "");
    rejects("consumerStatusCacheSeconds", "5");
    rejects("sortKeys", nlohmann::json::array());
    rejects("sortKeys", nlohmann::json::array({"offset"}));
    rejects("requiredDocumentIds", "FEED-GLOBAL");
    rejects("requiredDocumentIds", nlohmann::json::array({""}));
}

TEST(ExecutionContextTest, AcceptsAFullyPopulatedQueryShape)
{
    auto config = cursorConfig();
    config["indexer"]["pageSize"] = 500;
    config["indexer"]["numSlices"] = 2;
    config["indexer"]["keepAlive"] = "10m";
    config["indexer"]["expandWildcards"] = true;
    config["indexer"]["cursorField"] = "offset";
    config["indexer"]["consumerStatusCacheSeconds"] = 0;
    config["indexer"]["sortKeys"] = nlohmann::json::array({nlohmann::json {{"offset", "asc"}}});
    config["indexer"]["sourceFilter"] = nlohmann::json {{"excludes", nlohmann::json::array({"a.b"})}};
    config["indexer"]["requiredDocumentIds"] = nlohmann::json::array({"FEED-GLOBAL"});

    EXPECT_NO_THROW(ExecutionContext::validate(config));
}

TEST(ExecutionContextTest, DataIndicesPrefersTheExplicitList)
{
    nlohmann::json indexer {{"index", "ignored"}, {"indices", nlohmann::json::array({"a", "b"})}};
    EXPECT_EQ(ExecutionContext::dataIndices(indexer), (std::vector<std::string> {"a", "b"}));

    nlohmann::json single {{"index", "only"}};
    EXPECT_EQ(ExecutionContext::dataIndices(single), (std::vector<std::string> {"only"}));
}

TEST(ExecutionContextTest, PrepareBuildsTheUserAgentAndOpensNoDatabaseWithoutAPath)
{
    const auto context = ExecutionContext::prepare(cursorConfig(), "topic");

    EXPECT_EQ(context.httpUserAgent.rfind("Test Consumer/", 0), 0U);
    // A host that owns its own state (the engine keeps tokens in its store) omits databasePath, and
    // then no RocksDB is opened at all.
    EXPECT_EQ(context.database, nullptr);
}
