#include <gtest/gtest.h>

#include "hlp_test.hpp"

auto constexpr NAME = "fileParser";
static const std::string TARGET = "/TargetField";

INSTANTIATE_TEST_SUITE_P(FileBuild,
                         HlpBuildTest,
                         ::testing::Values(BuildT(FAILURE, getFilePathParser, {NAME, TARGET, {}, {}}),
                                           BuildT(SUCCESS, getFilePathParser, {NAME, TARGET, {""}, {}}),
                                           BuildT(FAILURE, getFilePathParser, {NAME, TARGET, {""}, {"unexpected"}})));

INSTANTIATE_TEST_SUITE_P(
    FileParse,
    HlpParseTest,
    ::testing::Values(
        ParseT(SUCCESS,
               R"(/user/login.php)",
               j(fmt::format(R"({{"{}": {{"path":"/user","name":"login.php","ext":"php"}}}})", TARGET.substr(1))),
               15,
               getFilePathParser,
               {NAME, TARGET, {""}, {}}),
        ParseT(SUCCESS,
               R"(..\Windows\..\Users\"Administrator\rootkit.exe)",
               j(fmt::format(
                   R"({{"{}": {{"path":"..\\Windows\\..\\Users\\\"Administrator","name":"rootkit.exe","ext":"exe"}}}})",
                   TARGET.substr(1))),
               46,
               getFilePathParser,
               {NAME, TARGET, {""}, {}}),
        ParseT(SUCCESS,
               R"(/home/user/.rootkit/.file.sh)",
               j(fmt::format(R"({{"{}": {{"path": "/home/user/.rootkit","name": ".file.sh","ext": "sh"}}}})",
                             TARGET.substr(1))),
               28,
               getFilePathParser,
               {NAME, TARGET, {""}, {}}),
        ParseT(
            SUCCESS,
            R"(C:\Windows\System32\virus.exe)",
            j(fmt::format(
                R"({{"{}": {{"path": "C:\\Windows\\System32","name": "virus.exe","ext": "exe","drive_letter": "C"}}}})",
                TARGET.substr(1))),
            29,
            getFilePathParser,
            {NAME, TARGET, {""}, {}}),
        ParseT(SUCCESS,
               R"(../home/..user/.rootkit/..file.sh)",
               j(fmt::format(R"({{"{}": {{"path": "../home/..user/.rootkit","name": "..file.sh","ext": "sh"}}}})",
                             TARGET.substr(1))),
               33,
               getFilePathParser,
               {NAME, TARGET, {""}, {}}),
        ParseT(SUCCESS,
               R"(relative.test.log)",
               j(fmt::format(R"({{"{}": {{"path":"relative.test.log","name":"relative.test.log","ext":"log"}}}})",
                             TARGET.substr(1))),
               17,
               getFilePathParser,
               {NAME, TARGET, {""}, {}}),
        ParseT(SUCCESS,
               R"(.hidden.log)",
               j(fmt::format(R"({{"{}": {{"path":".hidden.log","name":".hidden.log","ext":"log"}}}})",
                             TARGET.substr(1))),
               11,
               getFilePathParser,
               {NAME, TARGET, {""}, {}}),
        ParseT(SUCCESS,
               R"(/)",
               j(fmt::format(R"({{"{}": {{"path":"/","name":"","ext":""}}}})", TARGET.substr(1))),
               1,
               getFilePathParser,
               {NAME, TARGET, {""}, {}})));
