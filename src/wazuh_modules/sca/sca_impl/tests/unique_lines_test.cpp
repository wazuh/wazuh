#include <unique_lines.hpp>

#include <gtest/gtest.h>

TEST(UniqueLinesTest, NewLinesAreEmptyAndJoinToNothing)
{
    const UniqueLines lines;

    EXPECT_TRUE(lines.Empty());
    EXPECT_EQ(lines.Join(), "");
}

TEST(UniqueLinesTest, LinesJoinInTheOrderTheyWereAdded)
{
    UniqueLines lines;

    lines.Add("Command execution failed: modprobe -n -v cramfs");
    lines.Add("Command execution failed: lsmod");

    EXPECT_FALSE(lines.Empty());
    EXPECT_EQ(lines.Join(),
              "Command execution failed: modprobe -n -v cramfs\n"
              "Command execution failed: lsmod");
}

TEST(UniqueLinesTest, RepeatedLineIsKeptOnce)
{
    UniqueLines lines;

    lines.Add("Path '/etc/modprobe.d/' does not exist");
    lines.Add("Command execution failed: lsmod");
    lines.Add("Path '/etc/modprobe.d/' does not exist");

    EXPECT_EQ(lines.Join(),
              "Path '/etc/modprobe.d/' does not exist\n"
              "Command execution failed: lsmod");
}

TEST(UniqueLinesTest, LineThatPrefixesAnotherIsNotADuplicate)
{
    UniqueLines lines;

    lines.Add("Command execution failed: lsmod -a");
    lines.Add("Command execution failed: lsmod");

    EXPECT_EQ(lines.Join(),
              "Command execution failed: lsmod -a\n"
              "Command execution failed: lsmod");
}

TEST(UniqueLinesTest, EmptyLinesAreIgnored)
{
    UniqueLines lines;

    lines.Add("");

    EXPECT_TRUE(lines.Empty());

    lines.Add("File '/etc/aide/aide.conf' does not exist or is not a regular file");
    lines.Add("");

    EXPECT_EQ(lines.Join(), "File '/etc/aide/aide.conf' does not exist or is not a regular file");
}
