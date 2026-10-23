/*
 * Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Usage: ebpf_syscalls_test <root with lib/modern.bpf.o and tmp/> <dir>... */

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <grp.h>
#include <map>
#include <mutex>
#include <optional>
#include <pwd.h>
#include <string>
#include <string_view>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

#include "ebpf_whodata.h"

namespace fs = std::filesystem;

using Event = std::map<std::string, std::string, std::less<>>;

constexpr uid_t RUID = 1234;
constexpr uid_t EUID = 1235;
constexpr gid_t GID = 4321;
constexpr auto EVENT_TIMEOUT = std::chrono::seconds(5);
constexpr std::string_view RED = "\033[31m";
constexpr std::string_view GREEN = "\033[32m";
constexpr std::string_view RESET = "\033[0m";

static fs::path g_root;
static std::vector<fs::path> g_dirs;
static std::vector<Event> g_events;
static std::mutex g_mutex;
static std::condition_variable g_cv;

struct Syscall
{
    std::string_view name;
    bool needs_file;
    int (*run)(const char* path, int fd);
};

static const Syscall SYSCALLS[] = {
    // clang-format off
    {"open(O_CREAT)", false, [](const char* p, int) { return close(open(p, O_CREAT | O_WRONLY | O_EXCL, 0644)); }},
    {"open(O_TRUNC)", true, [](const char* p, int) { return close(open(p, O_WRONLY | O_TRUNC)); }},
    {"chmod", true, [](const char* p, int) { return chmod(p, 0600); }},
    {"fchmod", true, [](const char*, int fd) { return fchmod(fd, 0600); }},
    {"chown", true, [](const char* p, int) { return chown(p, EUID, GID); }},
    {"fchown", true, [](const char*, int fd) { return fchown(fd, EUID, GID); }},
    {"utimensat", true, [](const char* p, int) { return utimensat(AT_FDCWD, p, nullptr, 0); }},
    {"futimens", true, [](const char*, int fd) { return futimens(fd, nullptr); }},
    {"truncate", true, [](const char* p, int) { return truncate(p, 1); }},
    {"ftruncate", true, [](const char*, int fd) { return ftruncate(fd, 1); }},
    {"rename", false, [](const char* p, int) {
        const std::string old = std::string(p) + ".old";
        return close(open(old.c_str(), O_CREAT | O_WRONLY, 0644)) | rename(old.c_str(), p);
    }},
    {"unlink", true, [](const char* p, int) { return unlink(p); }},
    // clang-format on
};

static std::string str(const char* s)
{
    return s ? s : "";
}

static std::string read_line(const fs::path& path)
{
    std::string line;
    std::getline(std::ifstream(path), line);
    return line;
}

static bool in_test_dirs(const char* path)
{
    return std::any_of(g_dirs.begin(),
                       g_dirs.end(),
                       [path](const fs::path& dir) { return std::string_view(path).rfind(dir.native(), 0) == 0; });
}

static void on_event(whodata_evt* w)
{
    const std::lock_guard lock(g_mutex);
    Event& e = g_events.emplace_back();
    e["path"] = str(w->path);
    e["process_name"] = str(w->process_name);
    e["process_id"] = std::to_string(w->process_id);
    e["ppid"] = std::to_string(w->ppid);
    e["parent_name"] = str(w->parent_name);
    e["user_id"] = str(w->user_id);
    e["group_id"] = str(w->group_id);
    e["effective_uid"] = str(w->effective_uid);
    e["audit_uid"] = str(w->audit_uid);
    e["audit_gid"] = str(w->audit_gid);
    e["cwd"] = str(w->cwd);
    e["parent_cwd"] = str(w->parent_cwd);
    e["inode"] = str(w->inode);
    e["dev"] = str(w->dev);
    g_cv.notify_all();
}

static void free_event(whodata_evt* w)
{
    for (char* field : {w->user_id,
                        w->user_name,
                        w->process_name,
                        w->path,
                        w->group_id,
                        w->group_name,
                        w->audit_uid,
                        w->audit_name,
                        w->audit_gid,
                        w->audit_group_name,
                        w->effective_uid,
                        w->effective_name,
                        w->inode,
                        w->dev,
                        w->parent_name,
                        w->parent_cwd,
                        w->cwd})
    {
        free(field);
    }
    free(w);
}

static void log_msg(modules_log_level_t level, const char* msg)
{
    if (level == LOG_ERROR || level == LOG_WARNING)
    {
        printf("%s%s%s\n", RED.data(), msg, RESET.data());
    }
}

static char* root_path(const char* path, char* buffer, size_t size)
{
    snprintf(buffer, size, "%s", (g_root / path).c_str());
    return buffer;
}

static void make_file(const fs::path& path)
{
    std::ofstream(path) << "data\n";
    if (chown(path.c_str(), EUID, GID))
    {
        perror(path.c_str());
    }
}

/* Runs the syscall in a child with distinct IDs, comm and cwd */
static std::optional<pid_t> run_child(const Syscall& sc, const fs::path& dir, const fs::path& file, int fd)
{
    const pid_t pid = fork();
    if (pid == 0)
    {
        prctl(PR_SET_NAME, "wz_syscall");
        const bool ok = !setgroups(0, nullptr) && !setresgid(GID, GID, GID) && !setresuid(RUID, EUID, EUID) &&
                        !chdir(dir.c_str()) && !sc.run(file.c_str(), fd);
        _exit(ok ? 0 : 1);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? std::optional(pid) : std::nullopt;
}

static std::optional<Event> wait_event(pid_t pid, std::string_view path)
{
    std::unique_lock lock(g_mutex);
    std::optional<Event> found;
    g_cv.wait_for(lock,
                  EVENT_TIMEOUT,
                  [&]()
                  {
                      const auto it =
                          std::find_if(g_events.begin(),
                                       g_events.end(),
                                       [&](const Event& e)
                                       { return e.at("process_id") == std::to_string(pid) && e.at("path") == path; });
                      if (it != g_events.end())
                      {
                          found = *it;
                      }
                      return found.has_value();
                  });
    return found;
}

int main(int argc, char** argv)
{
    if (argc < 3)
    {
        fprintf(stderr, "Usage: %s <root> <dir>...\n", argv[0]);
        return 2;
    }
    g_root = argv[1];
    for (int i = 2; i < argc; i++)
    {
        fs::permissions(argv[i], fs::perms::all);
        g_dirs.emplace_back(fs::canonical(argv[i]));
    }

    fimebpf_initialize(
        in_test_dirs,
        [](int) -> char* { return nullptr; },
        [](int) -> char* { return nullptr; },
        on_event,
        free_event,
        log_msg,
        root_path,
        []() { return false; },
        4096);

    if (ebpf_whodata_healthcheck())
    {
        printf("%seBPF healthcheck failed%s\n", RED.data(), RESET.data());
        return 1;
    }
    std::thread(ebpf_whodata).detach();

    std::string login_uid = read_line("/proc/self/loginuid");
    std::string login_gid;
    if (login_uid == "4294967295")
    {
        login_uid.clear();
    }
    else if (const passwd* pw = getpwuid(std::stoul(login_uid)))
    {
        login_gid = std::to_string(pw->pw_gid);
    }

    utsname kernel {};
    uname(&kernel);
    int major = 0;
    int minor = 0;
    sscanf(kernel.release, "%d.%d", &major, &minor);
    // TODO: remove once #40452 (6.18 renamedata layout) is merged into this branch
    const bool skip_rename = std::pair(major, minor) >= std::pair(6, 18);

    int checks = 0;
    int failures = 0;
    for (const auto& dir : g_dirs)
    {
        for (const auto& sc : SYSCALLS)
        {
            if (skip_rename && sc.name == "rename")
            {
                continue;
            }
            const fs::path file = dir / sc.name;
            fs::remove(file);
            if (sc.needs_file)
            {
                make_file(file);
            }
            const int fd = sc.needs_file ? open(file.c_str(), O_RDWR) : -1;
            struct stat before = {};
            stat(file.c_str(), &before);

            const auto pid = run_child(sc, dir, file, fd);
            close(fd);
            const auto event = pid ? wait_event(*pid, file.native()) : std::nullopt;

            std::vector<std::string> errors;
            if (!pid)
            {
                errors.emplace_back("syscall failed");
            }
            else if (!event)
            {
                errors.emplace_back("no event");
            }
            else
            {
                struct stat after = {};
                const struct stat& st = stat(file.c_str(), &after) == 0 ? after : before;
                const Event expected = {{"process_name", "wz_syscall"},
                                        {"process_id", std::to_string(*pid)},
                                        {"ppid", std::to_string(getpid())},
                                        {"parent_name", read_line("/proc/self/comm")},
                                        {"user_id", std::to_string(RUID)},
                                        {"group_id", std::to_string(GID)},
                                        {"effective_uid", std::to_string(EUID)},
                                        {"audit_uid", login_uid},
                                        {"audit_gid", login_gid},
                                        {"cwd", dir},
                                        {"parent_cwd", fs::current_path()},
                                        {"inode", std::to_string(st.st_ino)},
                                        {"dev", std::to_string(st.st_dev)}};
                for (const auto& [field, value] : expected)
                {
                    if (event->at(field) != value)
                    {
                        errors.emplace_back(field + ": expected '" + value + "' got '" + event->at(field) + "'");
                    }
                }
            }

            checks++;
            failures += !errors.empty();
            for (const auto& error : errors)
            {
                printf("%s%s: %s%s\n", RED.data(), file.c_str(), error.c_str(), RESET.data());
            }
            fs::remove(file);
        }
    }

    const bool bpf_lsm = ("," + read_line("/sys/kernel/security/lsm") + ",").find(",bpf,") != std::string::npos;
    printf("%s%s%s: %d/%d passed%s\n",
           (failures ? RED : GREEN).data(),
           kernel.release,
           bpf_lsm ? " (BPF LSM)" : "",
           checks - failures,
           checks,
           RESET.data());
    fflush(stdout);
    _exit(failures ? 1 : 0);
}
