#include "reconcile/row_diff.hpp"

#include <gtest/gtest.h>

using namespace wazuh::container_baseline;

namespace {

EmittedRow row(std::string id, std::string index, std::string json)
{
    return EmittedRow{std::move(id), kOperationCreate, std::move(index), std::move(json), 1};
}

} // namespace

TEST(RowDiff, NewRowIsCreate)
{
    FingerprintMap prior;
    const std::vector<EmittedRow> current{row("c1:proc:1", "idx", R"({"a":1})")};

    const auto delta = diffRows(prior, current);

    ASSERT_EQ(delta.creates.size(), 1u);
    EXPECT_EQ(delta.creates[0].id, "c1:proc:1");
    EXPECT_EQ(delta.creates[0].operation, kOperationCreate);
    EXPECT_EQ(delta.creates[0].version, 1u);
    EXPECT_TRUE(delta.modifies.empty());
    EXPECT_TRUE(delta.deletes.empty());
}

TEST(RowDiff, ChangedContentIsModifyWithBumpedVersion)
{
    FingerprintMap prior{{"c1:proc:1", RowFingerprint{"idx", contentHash(R"({"a":1})"), 3}}};
    const std::vector<EmittedRow> current{row("c1:proc:1", "idx", R"({"a":2})")};

    const auto delta = diffRows(prior, current);

    EXPECT_TRUE(delta.creates.empty());
    ASSERT_EQ(delta.modifies.size(), 1u);
    EXPECT_EQ(delta.modifies[0].operation, kOperationModify);
    EXPECT_EQ(delta.modifies[0].version, 4u);
    EXPECT_TRUE(delta.deletes.empty());
}

TEST(RowDiff, UnchangedContentEmitsNothing)
{
    FingerprintMap prior{{"c1:proc:1", RowFingerprint{"idx", contentHash(R"({"a":1})"), 1}}};
    const std::vector<EmittedRow> current{row("c1:proc:1", "idx", R"({"a":1})")};

    EXPECT_TRUE(diffRows(prior, current).empty());
}

TEST(RowDiff, MissingPriorRowIsDelete)
{
    FingerprintMap prior{{"c1:proc:gone", RowFingerprint{"idx", 42, 2}}};
    const std::vector<EmittedRow> current;

    const auto delta = diffRows(prior, current);

    ASSERT_EQ(delta.deletes.size(), 1u);
    EXPECT_EQ(delta.deletes[0].id, "c1:proc:gone");
    EXPECT_EQ(delta.deletes[0].index, "idx");
    EXPECT_TRUE(delta.creates.empty());
    EXPECT_TRUE(delta.modifies.empty());
}

TEST(RowDiff, EmptyIdRowIsSkipped)
{
    FingerprintMap prior;
    const std::vector<EmittedRow> current{row("", "idx", "{}")};

    EXPECT_TRUE(diffRows(prior, current).empty());
}

TEST(RowDiff, MixedCreateModifyDelete)
{
    FingerprintMap prior{
        {"keep", RowFingerprint{"idx", contentHash(R"({"v":1})"), 1}},
        {"change", RowFingerprint{"idx", contentHash(R"({"v":1})"), 1}},
        {"drop", RowFingerprint{"idx", 7, 1}},
    };
    const std::vector<EmittedRow> current{
        row("keep", "idx", R"({"v":1})"),
        row("change", "idx", R"({"v":2})"),
        row("add", "idx", R"({"v":9})"),
    };

    const auto delta = diffRows(prior, current);

    ASSERT_EQ(delta.creates.size(), 1u);
    EXPECT_EQ(delta.creates[0].id, "add");
    ASSERT_EQ(delta.modifies.size(), 1u);
    EXPECT_EQ(delta.modifies[0].id, "change");
    ASSERT_EQ(delta.deletes.size(), 1u);
    EXPECT_EQ(delta.deletes[0].id, "drop");
}
