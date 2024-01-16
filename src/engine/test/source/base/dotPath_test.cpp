#include <gtest/gtest.h>

#include "dotPath.hpp"

TEST(DotPathTest, BuildsDefault)
{
    ASSERT_NO_THROW(DotPath());
    DotPath dp;
    ASSERT_EQ(dp.str(), "");
    ASSERT_EQ(dp.parts().size(), 0);
}

TEST(DotPathTest, CBegin)
{
    DotPath dp;
    ASSERT_EQ(dp.cbegin(), dp.parts().cbegin());
}

TEST(DotPathTest, CEnd)
{
    DotPath dp;
    ASSERT_EQ(dp.cend(), dp.parts().cend());
}

TEST(DotPathTest, Ostream)
{
    DotPath dp;
    std::stringstream ss;
    ss << dp;
    ASSERT_EQ(ss.str(), "");
}

using EqualsTuple = std::tuple<DotPath, DotPath, bool>;
class Equals : public ::testing::TestWithParam<EqualsTuple>
{
};

TEST_P(Equals, Equals)
{
    auto [lhs, rhs, expected] = GetParam();

    if (expected)
    {
        ASSERT_EQ(lhs, rhs);
    }
    else
    {
        ASSERT_NE(lhs, rhs);
    }
}

INSTANTIATE_TEST_SUITE_P(DotPathTest,
                         Equals,
                         ::testing::Values(EqualsTuple({"a"}, {"a"}, true),
                                           EqualsTuple({"a"}, {"b"}, false),
                                           EqualsTuple({"a.b"}, {"a.b"}, true),
                                           EqualsTuple({"a.b"}, {"a.c"}, false)));

using BuildsStrTuple = std::tuple<std::string, std::vector<std::string>, bool>;
class BuildsStr : public ::testing::TestWithParam<BuildsStrTuple>
{
};

TEST_P(BuildsStr, Builds)
{
    auto [path, parts, shouldPass] = GetParam();

    if (shouldPass)
    {
        ASSERT_NO_THROW(DotPath{path});
        DotPath dp(path);
        ASSERT_EQ(dp.str(), path);
        ASSERT_EQ(dp.parts().size(), parts.size());
        for (auto i = 0; i < parts.size(); ++i)
        {
            ASSERT_EQ(parts[i], dp.parts()[i]);
        }
    }
    else
    {
        ASSERT_THROW(DotPath{path}, std::runtime_error);
    }
}

TEST_P(BuildsStr, Copies)
{
    auto [path, parts, shouldPass] = GetParam();
    if (shouldPass)
    {
        DotPath dp(path);
        DotPath cpyConstructor(dp);
        DotPath cpyAssignment;
        cpyAssignment = dp;

        ASSERT_EQ(cpyConstructor, dp);
        ASSERT_EQ(cpyAssignment, dp);
    }
}

TEST_P(BuildsStr, Moves)
{
    auto [path, parts, shouldPass] = GetParam();
    if (shouldPass)
    {

        DotPath expected(path);
        DotPath dp(path);
        DotPath mvConstructor(std::move(dp));
        DotPath mvAssignment;
        dp = DotPath(path);
        mvAssignment = std::move(dp);

        ASSERT_EQ(mvConstructor, expected);
        ASSERT_EQ(mvAssignment, expected);
    }
}

INSTANTIATE_TEST_SUITE_P(DotPathTest,
                         BuildsStr,
                         ::testing::Values(BuildsStrTuple("a", {"a"}, true),
                                           BuildsStrTuple("a.b", {"a", "b"}, true),
                                           BuildsStrTuple("a.b.c", {"a", "b", "c"}, true),
                                           BuildsStrTuple(".", {"",""}, true),
                                           BuildsStrTuple("", {}, false),
                                           BuildsStrTuple("a.", {}, false),
                                           BuildsStrTuple(".a", {}, false),
                                           BuildsStrTuple("a..b", {}, false),
                                           BuildsStrTuple("a\\.b", {"a.b"}, true),
                                           BuildsStrTuple("a\\.b.c", {"a.b", "c"}, true),
                                           BuildsStrTuple("a.b\\.c", {"a", "b.c"}, true)));
