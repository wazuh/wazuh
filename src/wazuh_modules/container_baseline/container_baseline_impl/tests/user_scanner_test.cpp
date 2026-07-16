#include "user_scanner.hpp"

#include <gtest/gtest.h>

using wazuh::container_baseline::GroupBaselineRow;
using wazuh::container_baseline::ParseGroupLine;
using wazuh::container_baseline::ParsePasswdLine;
using wazuh::container_baseline::UserBaselineRow;

TEST(ParsePasswdLine, ParsesStandardEntry)
{
    UserBaselineRow row;
    ASSERT_TRUE(ParsePasswdLine("root:x:0:0:root:/root:/bin/bash", row));
    EXPECT_EQ(row.name, "root");
    EXPECT_EQ(row.uid, 0);
    EXPECT_EQ(row.gid, 0);
    EXPECT_EQ(row.description, "root");
    EXPECT_EQ(row.home, "/root");
    EXPECT_EQ(row.shell, "/bin/bash");
}

TEST(ParsePasswdLine, ParsesNologinServiceAccount)
{
    UserBaselineRow row;
    ASSERT_TRUE(ParsePasswdLine("nginx:x:101:101:nginx user,,,:/nonexistent:/usr/sbin/nologin", row));
    EXPECT_EQ(row.name, "nginx");
    EXPECT_EQ(row.uid, 101);
    EXPECT_EQ(row.gid, 101);
    EXPECT_EQ(row.description, "nginx user,,,");
    EXPECT_EQ(row.shell, "/usr/sbin/nologin");
}

TEST(ParsePasswdLine, ParsesEmptyGecosAndShell)
{
    UserBaselineRow row;
    ASSERT_TRUE(ParsePasswdLine("bin:x:1:1::/bin:", row));
    EXPECT_EQ(row.name, "bin");
    EXPECT_TRUE(row.description.empty());
    EXPECT_TRUE(row.shell.empty());
}

TEST(ParsePasswdLine, RejectsBlankLine)
{
    UserBaselineRow row;
    EXPECT_FALSE(ParsePasswdLine("", row));
}

TEST(ParsePasswdLine, RejectsComment)
{
    UserBaselineRow row;
    EXPECT_FALSE(ParsePasswdLine("# a comment", row));
}

TEST(ParsePasswdLine, RejectsWrongFieldCount)
{
    UserBaselineRow row;
    EXPECT_FALSE(ParsePasswdLine("root:x:0:0:/root:/bin/bash", row));
    EXPECT_FALSE(ParsePasswdLine("root:x:0:0:root:/root:/bin/bash:extra", row));
}

TEST(ParsePasswdLine, RejectsNonNumericIds)
{
    UserBaselineRow row;
    EXPECT_FALSE(ParsePasswdLine("root:x:zero:0:root:/root:/bin/bash", row));
    EXPECT_FALSE(ParsePasswdLine("root:x:0:0abc:root:/root:/bin/bash", row));
}

TEST(ParsePasswdLine, RejectsEmptyName)
{
    UserBaselineRow row;
    EXPECT_FALSE(ParsePasswdLine(":x:0:0:root:/root:/bin/bash", row));
}

TEST(ParseGroupLine, ParsesEntryWithMembers)
{
    GroupBaselineRow row;
    ASSERT_TRUE(ParseGroupLine("adm:x:4:syslog,ubuntu", row));
    EXPECT_EQ(row.name, "adm");
    EXPECT_EQ(row.gid, 4);
    ASSERT_EQ(row.members.size(), 2u);
    EXPECT_EQ(row.members[0], "syslog");
    EXPECT_EQ(row.members[1], "ubuntu");
}

TEST(ParseGroupLine, ParsesEntryWithoutMembers)
{
    GroupBaselineRow row;
    ASSERT_TRUE(ParseGroupLine("root:x:0:", row));
    EXPECT_EQ(row.name, "root");
    EXPECT_EQ(row.gid, 0);
    EXPECT_TRUE(row.members.empty());
}

TEST(ParseGroupLine, RejectsWrongFieldCount)
{
    GroupBaselineRow row;
    EXPECT_FALSE(ParseGroupLine("root:x:0", row));
    EXPECT_FALSE(ParseGroupLine("root:x:0::extra", row));
}

TEST(ParseGroupLine, RejectsNonNumericGid)
{
    GroupBaselineRow row;
    EXPECT_FALSE(ParseGroupLine("root:x:g0:", row));
}

TEST(ScanContainerUsers, MissingRootfsYieldsEmpty)
{
    EXPECT_TRUE(wazuh::container_baseline::ScanContainerUsers(-1).empty());
}

TEST(ScanContainerGroups, MissingRootfsYieldsEmpty)
{
    EXPECT_TRUE(wazuh::container_baseline::ScanContainerGroups(-1).empty());
}
