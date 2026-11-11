// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef _CMSYNC_TEST_CAPTURELOGS
#define _CMSYNC_TEST_CAPTURELOGS

#include <string>

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

#endif // _CMSYNC_TEST_CAPTURELOGS
