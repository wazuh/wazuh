// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef _CMSYNC_TEST_CAPTURELOGS
#define _CMSYNC_TEST_CAPTURELOGS

#include <cstddef>
#include <sstream>
#include <string>
#include <string_view>

#include <gtest/gtest.h>

// Engine log lines of a call: INFO/DEBUG go to stdout, WARNING and above to stderr (base::logging CustomSink)
struct CapturedLogs
{
    std::string info;
    std::string warn;
};

template<typename Fn>
CapturedLogs captureLogs(Fn&& fn)
{
    testing::internal::CaptureStdout();
    testing::internal::CaptureStderr();
    fn();
    return {testing::internal::GetCapturedStdout(), testing::internal::GetCapturedStderr()};
}

// Number of captured lines logged at `level` ("debug", "info", "warning", "error") whose message contains `text`.
// The level is read from the test log header (base::logging DEFAULT_LOG_HEADER):
// "<date> <time> <pid>:<tid> <level>: <message>". stdout mixes INFO and DEBUG, stderr WARNING and ERROR, so the
// stream alone does not tell the level.
inline std::size_t countAtLevel(const std::string& output, std::string_view level, std::string_view text)
{
    std::size_t count {0};
    std::istringstream lines {output};
    for (std::string line; std::getline(lines, line);)
    {
        std::size_t levelStart {0};
        for (auto field = 0; field < 3 && levelStart != std::string::npos; ++field)
        {
            levelStart = line.find(' ', levelStart);
            if (levelStart != std::string::npos)
            {
                ++levelStart;
            }
        }
        if (levelStart == std::string::npos)
        {
            continue;
        }
        const auto levelEnd = line.find(": ", levelStart);
        if (levelEnd != std::string::npos && std::string_view(line).substr(levelStart, levelEnd - levelStart) == level
            && line.find(text, levelEnd + 2) != std::string::npos)
        {
            ++count;
        }
    }
    return count;
}

#endif // _CMSYNC_TEST_CAPTURELOGS
