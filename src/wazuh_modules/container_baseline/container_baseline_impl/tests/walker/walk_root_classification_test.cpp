/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * D17: telling "the root is not in this image" apart from "the root could not
 * be examined" (#37532, WP3 of 14-spike-integration-plan).
 *
 * WalkContainerPath() used to set one flag, root_missing, for ANY failure to
 * lstat the configured root. The consumer folded it into `partial`, which
 * suppresses delete detection — and because "this directory is not in the
 * image" is a STATIC condition, the suppression never lifted and that
 * container's deletions were never reported at all (C24).
 *
 * Separating the two is only safe because of one check, and this file exists
 * for it: /proc/<pid>/root/<path> also fails with ENOENT once the pid has
 * exited, so errno alone would report a whole vanished container as a set of
 * vanished directories — C15's mass false delete arriving one root at a time.
 * Case 4 is that property. It is the one that must never regress.
 *
 * Standalone, like the eBPF consumers' suites: `make check`. Needs
 * `make build TARGET=agent` to have produced src/build/lib. Runs as an
 * ordinary user; the permission case is skipped when running as root, where
 * nothing is unreadable.
 */

#include "rootfs_file_walker.hpp"

#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <string>

using wazuh::container_baseline::HashSelection;
using wazuh::container_baseline::WalkContainerPath;

namespace {

int g_failures = 0;

void Check(bool condition, const char* what)
{
    std::printf("  %-70s %s\n", what, condition ? "OK" : "FAIL");
    if (!condition) ++g_failures;
}

void Skip(const char* what, const char* why)
{
    std::printf("  %-70s SKIP (%s)\n", what, why);
}

/// A throwaway directory under /tmp, removed on destruction.
class TempDir
{
    public:
        TempDir()
        {
            char pattern[] = "/tmp/cb-walker-XXXXXX";
            const char* made = ::mkdtemp(pattern);
            if (made != nullptr) m_path = made;
        }

        ~TempDir()
        {
            if (m_path.empty()) return;
            ::chmod(m_path.c_str(), 0700);
            const std::string cmd = "rm -rf '" + m_path + "'";
            if (std::system(cmd.c_str()) != 0) { /* best effort */ }
        }

        TempDir(const TempDir&) = delete;
        TempDir& operator=(const TempDir&) = delete;

        [[nodiscard]] const std::string& path() const { return m_path; }

        void writeFile(const std::string& name, const char* content) const
        {
            std::FILE* f = std::fopen((m_path + "/" + name).c_str(), "w");
            if (f == nullptr) return;
            std::fputs(content, f);
            std::fclose(f);
        }

    private:
        std::string m_path;
};

/// /proc/self/root is the walker's entry point, and for an ordinary process it
/// is just "/", so an absolute host path doubles as an "in-container" path.
wazuh::container_baseline::WalkResult Walk(pid_t pid, const std::string& path)
{
    return WalkContainerPath(pid, path, 0, 0, 0, nullptr, HashSelection{}, {});
}

// --------------------------------------------------------------------- cases --

void CaseRootThatExists()
{
    std::printf("case 1: a root that exists is neither missing nor unreadable\n");

    TempDir dir;
    dir.writeFile("f.txt", "x");

    const auto result = Walk(::getpid(), dir.path());

    Check(!result.rows.empty(), "rows were produced");
    Check(!result.root_missing, "root_missing is clear");
    Check(!result.root_unreadable, "root_unreadable is clear");
    Check(!result.truncated, "truncated is clear");
}

void CaseRootAbsentFromTheImage()
{
    std::printf("case 2: a root that is simply not there is root_missing\n");

    const auto result = Walk(::getpid(), "/tmp/cb-walker-definitely-not-here-37532");

    Check(result.rows.empty(), "no rows");
    Check(result.root_missing, "root_missing is set — the walk looked, and it is not there");
    Check(!result.root_unreadable, "root_unreadable is clear: nothing failed");
}

void CaseRootNotADirectory()
{
    std::printf("case 3: a path under a regular file is root_missing (ENOTDIR)\n");

    TempDir dir;
    dir.writeFile("afile", "x");

    const auto result = Walk(::getpid(), dir.path() + "/afile/below");

    Check(result.rows.empty(), "no rows");
    Check(result.root_missing, "root_missing is set");
    Check(!result.root_unreadable, "root_unreadable is clear");
}

void CaseVanishedContainerIsNotAVanishedDirectory()
{
    std::printf("case 4: a dead pid is root_unreadable, NEVER root_missing\n");

    // The C15 shape. /proc/<dead pid>/root/<path> fails with ENOENT, so classing
    // it as "absent from the image" would authorise deleting every stored row
    // of a container that has merely gone away.
    const pid_t child = ::fork();

    if (child == 0)
    {
        ::_exit(0);
    }

    if (child < 0)
    {
        Skip("a dead pid is not reported as a missing root", "fork failed");
        return;
    }

    int status = 0;
    ::waitpid(child, &status, 0);

    // The pid is reaped, so /proc/<child> is gone.
    const auto result = Walk(child, "/tmp");

    Check(result.rows.empty(), "no rows");
    Check(!result.root_missing,
          "root_missing is CLEAR — a gone container is not a gone directory (C15)");
    Check(result.root_unreadable, "root_unreadable is set: nothing is known about this root");
}

void CaseUnreadableRoot()
{
    std::printf("case 5: a root that cannot be traversed is root_unreadable\n");

    if (::geteuid() == 0)
    {
        Skip("an unreadable root is not reported as a missing root", "running as root");
        return;
    }

    TempDir dir;
    const std::string blocked = dir.path() + "/blocked";

    if (::mkdir(blocked.c_str(), 0700) != 0)
    {
        Skip("an unreadable root is not reported as a missing root", "mkdir failed");
        return;
    }

    // No execute bit on the parent, so resolving anything beneath it is EACCES
    // rather than ENOENT.
    if (::chmod(dir.path().c_str(), 0000) != 0)
    {
        Skip("an unreadable root is not reported as a missing root", "chmod failed");
        return;
    }

    const auto result = Walk(::getpid(), blocked);

    ::chmod(dir.path().c_str(), 0700);

    Check(result.rows.empty(), "no rows");
    Check(!result.root_missing, "root_missing is CLEAR — we could not look, so we know nothing");
    Check(result.root_unreadable, "root_unreadable is set");
}

} // namespace

int main()
{
    CaseRootThatExists();
    CaseRootAbsentFromTheImage();
    CaseRootNotADirectory();
    CaseVanishedContainerIsNotAVanishedDirectory();
    CaseUnreadableRoot();

    std::printf("\n%s\n", g_failures == 0 ? "ALL OK" : "FAILURES");
    return g_failures == 0 ? 0 : 1;
}
