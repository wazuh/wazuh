#include <memory>
#include <set>
#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <base/logging.hpp>
#include <iockvdb/helpers.hpp>
#include <iockvdb/mockManager.hpp>

#include <cmcontent/iocTypeSink.hpp>

using namespace cmcontent;
using namespace ::testing;

namespace
{

/// The type used throughout; its target database name comes from the IOC type table.
constexpr auto IOC_TYPE = "url_domain";

content_manager::SessionInfo sessionOf(content_manager::SessionKind kind)
{
    content_manager::SessionInfo info;
    info.topic = "content.ioc.url_domain";
    info.kind = kind;
    info.remoteToken = "hash-1";
    return info;
}

nlohmann::json pageWith(const std::vector<std::string>& names)
{
    auto hits = nlohmann::json::array();
    for (const auto& name : names)
    {
        hits.push_back(nlohmann::json {
            {"_id", name},
            {"_source", {{"document", {{"name", name}, {"type", IOC_TYPE}, {"confidence", 50}}}}}});
    }
    return hits;
}

content_manager::ContentPage pageOf(const nlohmann::json& hits)
{
    content_manager::ContentPage page;
    page.topic = "content.ioc.url_domain";
    page.hits = &hits;
    return page;
}

class IocTypeSinkTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        logging::testInit();
        kvdb = std::make_shared<NiceMock<ioc::kvdb::MockKVDBManager>>();
        sink = std::make_shared<IocTypeSink>(kvdb, IOC_TYPE);
        targetDb = std::string {ioc::kvdb::details::getDbNameFromType(IOC_TYPE)};

        // `exists` answers from a real set rather than a fixed value. A mock that reports every
        // database as present forever makes cleanup look like it runs twice — the sink probes before
        // removing, so a lying `exists` turns one removal into two — and that is a property of the
        // mock, not of the code. Modelling it costs three lines and removes a whole class of
        // false failures.
        ON_CALL(*kvdb, add(_))
            .WillByDefault(Invoke([this](std::string_view name) { existing.emplace(name); }));
        ON_CALL(*kvdb, remove(_))
            .WillByDefault(Invoke([this](std::string_view name) { existing.erase(std::string {name}); }));
        ON_CALL(*kvdb, exists(_))
            .WillByDefault(
                Invoke([this](std::string_view name) { return existing.count(std::string {name}) != 0; }));
        ON_CALL(*kvdb, hotSwap(_, _))
            .WillByDefault(Invoke(
                [this](std::string_view source, std::string_view target)
                {
                    // The real swap invalidates the source and leaves the target holding its data.
                    existing.erase(std::string {source});
                    existing.emplace(target);
                }));
    }

    /// The staging database name the sink uses for this type: fixed, so a crash leaves something
    /// the next session can still find and reclaim.
    static std::string stagingDb() { return std::string {"iocsync_"} + IOC_TYPE + "_staging"; }

    std::shared_ptr<NiceMock<ioc::kvdb::MockKVDBManager>> kvdb;
    std::shared_ptr<IocTypeSink> sink;
    std::string targetDb;
    std::set<std::string> existing;
};

} // namespace

TEST_F(IocTypeSinkTest, NoChangeIsSkippedWithoutTouchingTheDatabase)
{
    EXPECT_CALL(*kvdb, add(_)).Times(0);

    // A NoChange session carries no documents, so there would be nothing to swap in. Rebuilding a
    // physically missing database is the caller's job: it asks for a forced full reload instead.
    EXPECT_EQ(sink->beginSession(sessionOf(content_manager::SessionKind::NoChange)),
              content_manager::SessionDecision::Skip);
}

TEST_F(IocTypeSinkTest, FullReloadStagesIntoATemporaryDatabase)
{
    std::string staged;
    EXPECT_CALL(*kvdb, add(_)).WillOnce(Invoke([&staged](std::string_view name) { staged = std::string {name}; }));

    EXPECT_EQ(sink->beginSession(sessionOf(content_manager::SessionKind::FullReload)),
              content_manager::SessionDecision::Proceed);

    // Never the target: readers keep seeing the old database until the swap.
    EXPECT_NE(staged, targetDb);
    // Fixed, not random: a name that only exists in the memory of the process that created it
    // cannot be reclaimed after that process dies.
    EXPECT_EQ(staged, stagingDb());
}

TEST_F(IocTypeSinkTest, AStagingDatabaseLeftByAPreviousRunIsReclaimed)
{
    // No prior session on this object: this is what a crash mid-sync leaves behind, and the only
    // reason it is recoverable is that the name is derived from the type rather than invented.
    existing.emplace(stagingDb());

    EXPECT_CALL(*kvdb, remove(StrEq(stagingDb()))).Times(1);
    EXPECT_CALL(*kvdb, add(StrEq(stagingDb()))).Times(1);

    EXPECT_EQ(sink->beginSession(sessionOf(content_manager::SessionKind::FullReload)),
              content_manager::SessionDecision::Proceed);
}

TEST_F(IocTypeSinkTest, DocumentsAreStoredUnderALowercasedKey)
{
    ON_CALL(*kvdb, get(_, _)).WillByDefault(Return(std::nullopt));

    std::vector<std::string> keys;
    EXPECT_CALL(*kvdb, put(_, _, _))
        .WillRepeatedly(
            Invoke([&keys](std::string_view, std::string_view key, std::string_view) { keys.emplace_back(key); }));

    ASSERT_EQ(sink->beginSession(sessionOf(content_manager::SessionKind::FullReload)),
              content_manager::SessionDecision::Proceed);

    const auto hits = pageWith({"Evil.EXAMPLE.com", "other.example.com"});
    EXPECT_EQ(sink->acceptPage(pageOf(hits)).status, content_manager::PageStatus::Accepted);

    // Indicators arrive with whatever casing the feed used; lookups have their own.
    EXPECT_EQ(keys, (std::vector<std::string> {"evil.example.com", "other.example.com"}));
}

TEST_F(IocTypeSinkTest, MalformedDocumentsAreSkippedNotRejected)
{
    ON_CALL(*kvdb, get(_, _)).WillByDefault(Return(std::nullopt));
    EXPECT_CALL(*kvdb, put(_, _, _)).Times(1);

    ASSERT_EQ(sink->beginSession(sessionOf(content_manager::SessionKind::FullReload)),
              content_manager::SessionDecision::Proceed);

    auto hits = nlohmann::json::array();
    hits.push_back(nlohmann::json {{"_id", "a"}});                                              // no _source
    hits.push_back(nlohmann::json {{"_id", "b"}, {"_source", nlohmann::json::object()}});       // no document
    hits.push_back(nlohmann::json {{"_id", "c"}, {"_source", {{"document", {{"type", "x"}}}}}}); // no name
    hits.push_back(pageWith({"good.example.com"}).front());

    // One bad document must not throw away a whole feed; the page still carries the good ones.
    EXPECT_EQ(sink->acceptPage(pageOf(hits)).status, content_manager::PageStatus::Accepted);
}

TEST_F(IocTypeSinkTest, CommitCreatesTheTargetWhenMissingAndHotSwaps)
{
    ASSERT_EQ(sink->beginSession(sessionOf(content_manager::SessionKind::FullReload)),
              content_manager::SessionDecision::Proceed);
    ASSERT_EQ(existing.count(stagingDb()), 1U);
    ASSERT_EQ(existing.count(targetDb), 0U);

    EXPECT_CALL(*kvdb, add(StrEq(targetDb))).Times(1);
    EXPECT_CALL(*kvdb, hotSwap(StrEq(stagingDb()), StrEq(targetDb))).Times(1);

    content_manager::CommitInfo info;
    info.topic = "content.ioc.url_domain";
    info.finalToken = "hash-1";

    EXPECT_EQ(sink->commit(info).status, content_manager::CommitStatus::Committed);

    // The swap consumed the staging database, so nothing is left to clean up afterwards.
    EXPECT_EQ(existing.count(stagingDb()), 0U);
    EXPECT_EQ(existing.count(targetDb), 1U);
}

TEST_F(IocTypeSinkTest, AFailedSwapRollsBackTheStagingDatabase)
{
    ON_CALL(*kvdb, hotSwap(_, _)).WillByDefault(Throw(std::runtime_error("swap failed")));

    ASSERT_EQ(sink->beginSession(sessionOf(content_manager::SessionKind::FullReload)),
              content_manager::SessionDecision::Proceed);

    EXPECT_CALL(*kvdb, remove(StrEq(stagingDb()))).Times(1);

    // RetrySame, not RetryFull: the failure is in the promotion, not in the content, so the remote
    // hash is still the one to fetch — and the stored token still describes the live database.
    EXPECT_EQ(sink->commit({}).status, content_manager::CommitStatus::RejectedRetrySame);
    EXPECT_EQ(existing.count(stagingDb()), 0U);
}

TEST_F(IocTypeSinkTest, AbortRemovesTheStagingDatabase)
{
    ASSERT_EQ(sink->beginSession(sessionOf(content_manager::SessionKind::FullReload)),
              content_manager::SessionDecision::Proceed);

    EXPECT_CALL(*kvdb, remove(StrEq(stagingDb()))).Times(1);
    sink->abort(content_manager::AbortReason::StopRequested, "shutting down");
    EXPECT_EQ(existing.count(stagingDb()), 0U);
}

TEST_F(IocTypeSinkTest, ASecondSessionDiscardsAnAbandonedStagingDatabase)
{
    ASSERT_EQ(sink->beginSession(sessionOf(content_manager::SessionKind::FullReload)),
              content_manager::SessionDecision::Proceed);
    ASSERT_EQ(existing.count(stagingDb()), 1U);

    // A cycle that died without commit or abort must not leak its staging database forever.
    EXPECT_CALL(*kvdb, remove(StrEq(stagingDb()))).Times(1);
    EXPECT_EQ(sink->beginSession(sessionOf(content_manager::SessionKind::FullReload)),
              content_manager::SessionDecision::Proceed);
    EXPECT_EQ(existing.count(stagingDb()), 1U);
}

TEST_F(IocTypeSinkTest, ADeadManagerAbortsTheSessionRatherThanCrashing)
{
    auto orphan = std::make_shared<IocTypeSink>(std::weak_ptr<ioc::kvdb::IKVDBManager> {}, IOC_TYPE);
    EXPECT_EQ(orphan->beginSession(sessionOf(content_manager::SessionKind::FullReload)),
              content_manager::SessionDecision::Abort);
}
