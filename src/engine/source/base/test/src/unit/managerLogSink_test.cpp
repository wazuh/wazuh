#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <cerrno>
#include <cstdarg>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <optional>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <tuple>
#include <vector>

#include <fcntl.h>
#include <grp.h>
#include <sys/stat.h>
#include <unistd.h>

#include <base/logging.hpp>
#include <base/managerLogSink.hpp>
#include <base/process.hpp>

namespace fs = std::filesystem;
using base::logging::ManagerLogDeps;
using base::logging::ManagerLogOptions;
using ::logging::Level;

namespace
{
constexpr auto NOW = "2026/10/14 12:34:56";
constexpr auto TAG = "wazuh-manager-analysisd";
constexpr int APPEND_FLAGS = O_WRONLY | O_APPEND | O_CLOEXEC;
constexpr int CREATE_FLAGS = O_WRONLY | O_APPEND | O_CREAT | O_EXCL | O_CLOEXEC;

/// Directory per test case (shared by a threadsafe death test child, which re-runs SetUp).
fs::path caseDir()
{
    const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
    return fs::temp_directory_path()
           / (std::string("base_manager_utest_") + info->test_suite_name() + "_" + info->name());
}

std::string readFile(const fs::path& path)
{
    std::ifstream file(path, std::ios::binary);
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

std::vector<std::string> splitLines(const std::string& content)
{
    std::vector<std::string> lines;
    std::string::size_type start = 0;
    while (start < content.size())
    {
        const auto end = content.find('\n', start);
        if (end == std::string::npos)
        {
            lines.push_back(content.substr(start)); // Unterminated tail: reported as a line of its own
            break;
        }
        lines.push_back(content.substr(start, end - start));
        start = end + 1;
    }
    return lines;
}

/// Current umask read from /proc (without changing it).
std::string procUmask()
{
    std::ifstream status("/proc/self/status");
    std::string line;
    while (std::getline(status, line))
    {
        if (line.rfind("Umask:", 0) == 0)
        {
            return line;
        }
    }
    return {};
}

/// Fake system calls: a tiny in-memory file system keyed by path, with every call recorded.
struct FakeSys
{
    struct OpenCall
    {
        std::string path;
        int flags;
        mode_t mode;
    };

    std::string now {NOW};
    int pid {4242};
    bool root {false};
    std::optional<gid_t> gid {};

    std::set<std::string> existing;
    std::map<int, std::string> fdPath;
    int nextFd {1000};

    std::vector<OpenCall> opens;
    std::vector<std::pair<int, mode_t>> fchmods;
    std::vector<std::tuple<int, uid_t, gid_t>> fchowns;
    std::vector<std::pair<int, std::string>> writes;
    std::vector<int> closes;
    std::vector<std::string> groupQueries;

    /// Optional override of open(): returns std::nullopt to fall back to the default behaviour.
    std::function<std::optional<int>(const OpenCall&, std::size_t)> openHook;

    int defaultOpen(const OpenCall& call)
    {
        if ((call.flags & O_CREAT) != 0)
        {
            if ((call.flags & O_EXCL) != 0 && existing.count(call.path) != 0)
            {
                errno = EEXIST;
                return -1;
            }
            existing.insert(call.path);
        }
        else if (existing.count(call.path) == 0)
        {
            errno = ENOENT;
            return -1;
        }
        const int fd = nextFd++;
        fdPath[fd] = call.path;
        return fd;
    }

    std::string contentOf(const std::string& path) const
    {
        std::string out;
        for (const auto& [fd, data] : writes)
        {
            auto it = fdPath.find(fd);
            if (it != fdPath.end() && it->second == path)
            {
                out += data;
            }
        }
        return out;
    }

    std::string stderrContent() const
    {
        std::string out;
        for (const auto& [fd, data] : writes)
        {
            if (fd == STDERR_FILENO)
            {
                out += data;
            }
        }
        return out;
    }

    std::string pathOfWrite(std::size_t i) const
    {
        const int fd = writes.at(i).first;
        if (fd == STDERR_FILENO)
        {
            return "<stderr>";
        }
        auto it = fdPath.find(fd);
        return it == fdPath.end() ? "<unknown>" : it->second;
    }
};

ManagerLogDeps fakeDeps(const std::shared_ptr<FakeSys>& sys)
{
    ManagerLogDeps deps;
    deps.now = [sys]()
    {
        return sys->now;
    };
    deps.pid = [sys]()
    {
        return sys->pid;
    };
    deps.isRoot = [sys]()
    {
        return sys->root;
    };
    deps.groupId = [sys](const std::string& name)
    {
        sys->groupQueries.push_back(name);
        return sys->gid;
    };
    deps.open = [sys](const char* path, int flags, mode_t mode)
    {
        FakeSys::OpenCall call {path, flags, mode};
        sys->opens.push_back(call);
        if (sys->openHook)
        {
            if (auto rc = sys->openHook(call, sys->opens.size()))
            {
                if (*rc >= 0)
                {
                    sys->fdPath[*rc] = call.path;
                }
                return *rc;
            }
        }
        return sys->defaultOpen(call);
    };
    deps.fchown = [sys](int fd, uid_t uid, gid_t gid)
    {
        sys->fchowns.emplace_back(fd, uid, gid);
        return 0;
    };
    deps.fchmod = [sys](int fd, mode_t mode)
    {
        sys->fchmods.emplace_back(fd, mode);
        return 0;
    };
    deps.write = [sys](int fd, const char* data, size_t size)
    {
        sys->writes.emplace_back(fd, std::string(data, size));
        return static_cast<ssize_t>(size);
    };
    deps.close = [sys](int fd)
    {
        sys->closes.push_back(fd);
        return 0;
    };
    return deps;
}

/// Calls a library log function (GLOBAL_LOG_FUNCTION signature) with a printf format.
template<typename Fn>
void callLibrary(const Fn& fn, int level, const char* tag, const char* format, ...)
{
    va_list args;
    va_start(args, format);
    fn(level, tag, "/src/shared_modules/indexer_connector/src/indexerConnector.cpp", 77, "publish", format, args);
    va_end(args);
}

class ManagerLogSinkTest : public ::testing::Test
{
protected:
    fs::path m_dir;
    fs::path m_oldCwd;

    void SetUp() override
    {
        m_dir = caseDir();
        fs::remove_all(m_dir);
        fs::create_directories(m_dir / "logs");
        m_oldCwd = fs::current_path();
        fs::current_path(m_dir);
        base::logging::setManagerDebugLevel(0);
    }

    void TearDown() override
    {
        // Leave the sink inert (real calls, no destination) so no fake outlives its test.
        ManagerLogOptions inert;
        inert.logPlain = false;
        inert.logJson = false;
        inert.writeStderr = false;
        base::logging::initManager(inert);
        base::logging::setManagerDebugLevel(0);
        fs::current_path(m_oldCwd);
        fs::remove_all(m_dir);
    }

    std::string plainPath() const { return (m_dir / "logs" / "wazuh-manager.log").string(); }
    std::string jsonPath() const { return (m_dir / "logs" / "wazuh-manager.json").string(); }

    ManagerLogOptions options(bool plain, bool json, bool toStderr) const
    {
        ManagerLogOptions opts;
        opts.plainPath = plainPath();
        opts.jsonPath = jsonPath();
        opts.logPlain = plain;
        opts.logJson = json;
        opts.writeStderr = toStderr;
        return opts;
    }

    std::shared_ptr<FakeSys> initFake(bool plain, bool json, bool toStderr)
    {
        auto sys = std::make_shared<FakeSys>();
        base::logging::initManager(options(plain, json, toStderr), fakeDeps(sys));
        return sys;
    }
};

using ManagerLogSinkDeathTest = ManagerLogSinkTest;

std::string plainLine(const std::string& level, const std::string& text, const std::string& tag = TAG)
{
    return std::string(NOW) + " " + tag + ": " + level + ": " + text + "\n";
}

} // namespace

// ---------------------------------------------------------------------------------------------------------------------
// Sink
// ---------------------------------------------------------------------------------------------------------------------

TEST_F(ManagerLogSinkDeathTest, UninitializedIsNoop)
{
    // Threadsafe: the child re-executes this binary running only this test, so initManager() was never called in it.
    ::testing::FLAGS_gtest_death_test_style = "threadsafe";

    EXPECT_EXIT(
        {
            try
            {
                base::logging::write(Level::Critical, TAG, __FILE__, __LINE__, "f", "should not be written");
                base::logging::write(Level::Info, TAG, __FILE__, __LINE__, "f", "should not be written");
                LOG_ERROR("nor this one");
            }
            catch (...)
            {
                std::_Exit(3);
            }
            std::error_code ec;
            if (!fs::is_empty(fs::current_path() / "logs", ec) || ec)
            {
                std::_Exit(4);
            }
            if (std::distance(fs::directory_iterator(fs::current_path()), fs::directory_iterator()) != 1)
            {
                std::_Exit(5);
            }
            if (logging::should_log(Level::Debug) || logging::should_log(Level::Trace))
            {
                std::_Exit(6);
            }
            if (!logging::should_log(Level::Info) || !logging::should_log(Level::Err))
            {
                std::_Exit(7);
            }
            std::_Exit(0);
        },
        ::testing::ExitedWithCode(0),
        ::testing::IsEmpty());
}

TEST_F(ManagerLogSinkTest, PlainLevels)
{
    auto sys = initFake(true, false, false);

    base::logging::write(Level::Info, TAG, "/a/b/x.cpp", 1, "f", "info message");
    base::logging::write(Level::Warn, TAG, "/a/b/x.cpp", 2, "f", "warn message");
    base::logging::write(Level::Err, TAG, "/a/b/x.cpp", 3, "f", "error message");
    base::logging::write(Level::Critical, TAG, "/a/b/x.cpp", 4, "f", "critical message");
    // Level 0: neither debug nor trace reach the file
    base::logging::write(Level::Debug, TAG, "/a/b/x.cpp", 5, "f", "debug message");
    base::logging::write(Level::Trace, TAG, "/a/b/x.cpp", 6, "f", "trace message");

    EXPECT_EQ(sys->contentOf(plainPath()),
              plainLine("INFO", "info message") + plainLine("WARNING", "warn message")
                  + plainLine("ERROR", "error message") + plainLine("ERROR", "critical message"));
    EXPECT_EQ(base::logging::formatPlainLine(NOW, TAG, "INFO", "x"), plainLine("INFO", "x"));
}

TEST_F(ManagerLogSinkTest, JsonTwin)
{
    auto sys = initFake(true, true, false);

    // Special characters first; an "é" (C3 A9) straddles byte 65535 so the JSON cut splits it.
    const std::string head = "a\"b\\c\nd\x01"
                             "e\x1f"
                             "f\b\f\r\t/g\xc3\xa9h";
    const std::string escapedHead = "a\\\"b\\\\c\\nd\\u0001e\\u001ff\\b\\f\\r\\t/g\xc3\xa9h";
    std::string message = head;
    message.append(65534 - message.size(), 'x');
    message.append("\xc3\xa9"); // bytes 65534 and 65535
    message.append(70000 - message.size(), 'y');
    ASSERT_EQ(message.size(), 70000u);

    base::logging::write(Level::Info, TAG, "/a/b/x.cpp", 1, "f", message);

    // Plain: the whole message, not truncated
    EXPECT_EQ(sys->contentOf(plainPath()), plainLine("INFO", message));

    // JSON: first 65535 bytes of the message, escaped like cJSON_PrintUnformatted
    std::string expected = std::string("{\"timestamp\":\"") + NOW + "\",\"tag\":\"" + TAG
                           + "\",\"level\":\"info\",\"description\":\"" + escapedHead;
    expected.append(65534 - head.size(), 'x');
    expected.append("\xc3");
    expected.append("\"}\n");
    const auto json = sys->contentOf(jsonPath());
    EXPECT_EQ(json.size(), expected.size());
    EXPECT_TRUE(json == expected) << "JSON line differs; first 200 bytes: " << json.substr(0, 200);
}

TEST_F(ManagerLogSinkTest, JsonOnlyWritesNoPlain)
{
    auto sys = initFake(false, true, false);

    base::logging::write(Level::Warn, TAG, "/a/b/x.cpp", 1, "f", "only json");

    for (const auto& call : sys->opens)
    {
        EXPECT_NE(call.path, plainPath());
    }
    ASSERT_EQ(sys->writes.size(), 1u);
    EXPECT_EQ(sys->pathOfWrite(0), jsonPath());
    EXPECT_EQ(sys->contentOf(jsonPath()),
              std::string("{\"timestamp\":\"") + NOW + "\",\"tag\":\"" + TAG
                  + "\",\"level\":\"warning\",\"description\":\"only json\"}\n");
    EXPECT_TRUE(sys->contentOf(plainPath()).empty());
}

TEST_F(ManagerLogSinkTest, DebugPrefix)
{
    auto sys = initFake(true, true, false);
    const char* file = "/workspaces/wazuh/src/engine/source/router/src/router.cpp";

    // Level 1: debug lines with prefix, trace lines dropped
    base::logging::setManagerDebugLevel(1);
    sys->pid = 1234;
    base::logging::write(Level::Debug, TAG, file, 42, "route", "debug one");
    base::logging::write(Level::Trace, TAG, file, 43, "route", "trace one");
    sys->pid = 5678; // pid is evaluated per line
    base::logging::write(Level::Info, TAG, file, 44, "route", "info one");

    // Level 2: trace lines too, as DEBUG
    base::logging::setManagerDebugLevel(2);
    base::logging::write(Level::Trace, TAG, file, 45, "route", "trace two");

    const std::string now = NOW;
    const std::string tag = TAG;
    EXPECT_EQ(sys->contentOf(plainPath()),
              now + " " + tag + "[1234] router.cpp:42 at route(): DEBUG: debug one\n" + now + " " + tag
                  + "[5678] router.cpp:44 at route(): INFO: info one\n" + now + " " + tag
                  + "[5678] router.cpp:45 at route(): DEBUG: trace two\n");

    const auto jsonLine = [&](int pid, int line, const std::string& level, const std::string& text)
    {
        return "{\"timestamp\":\"" + now + "\",\"tag\":\"" + tag + "\",\"pid\":" + std::to_string(pid)
               + ",\"file\":\"router.cpp\",\"line\":" + std::to_string(line) + ",\"routine\":\"route\",\"level\":\""
               + level + "\",\"description\":\"" + text + "\"}\n";
    };
    EXPECT_EQ(sys->contentOf(jsonPath()),
              jsonLine(1234, 42, "debug", "debug one") + jsonLine(5678, 44, "info", "info one")
                  + jsonLine(5678, 45, "debug", "trace two"));
}

TEST_F(ManagerLogSinkTest, DebugPlainNotTruncated)
{
    auto sys = initFake(true, true, false);
    base::logging::setManagerDebugLevel(1);
    sys->pid = 1234;
    const std::string text(70000, 'x');
    base::logging::write(Level::Info, TAG, "/a/b/router.cpp", 7, "route", text);

    // Debug prefix branch: the plain line keeps the whole message, only the JSON description is cut at 65535 bytes
    EXPECT_EQ(sys->contentOf(plainPath()),
              std::string(NOW) + " " + TAG + "[1234] router.cpp:7 at route(): INFO: " + text + "\n");
    EXPECT_NE(sys->contentOf(jsonPath()).find("\"description\":\"" + std::string(65535, 'x') + "\"}"),
              std::string::npos);
}

TEST_F(ManagerLogSinkTest, ErrnoPreserved)
{
    auto sys = initFake(true, true, true);
    // The files do not exist yet: the sink sees ENOENT, creates them and writes; the caller's errno must survive
    errno = EINVAL;
    base::logging::write(Level::Info, TAG, "/a/x.cpp", 1, "f", "keep errno");
    EXPECT_EQ(errno, EINVAL);
    EXPECT_FALSE(sys->contentOf(plainPath()).empty());
}

TEST_F(ManagerLogSinkTest, OneWritePerLine)
{
    auto sys = initFake(true, true, true);

    constexpr int MESSAGES = 5;
    for (int i = 0; i < MESSAGES; ++i)
    {
        base::logging::write(Level::Info, TAG, "/a/x.cpp", i, "f", "message " + std::to_string(i));
    }

    ASSERT_EQ(sys->writes.size(), static_cast<std::size_t>(3 * MESSAGES));
    for (std::size_t i = 0; i < sys->writes.size(); ++i)
    {
        const auto& data = sys->writes[i].second;
        ASSERT_FALSE(data.empty());
        EXPECT_EQ(data.back(), '\n') << "write " << i;
        EXPECT_EQ(std::count(data.begin(), data.end(), '\n'), 1) << "write " << i;
    }
    for (int i = 0; i < MESSAGES; ++i)
    {
        const auto msg = "message " + std::to_string(i);
        EXPECT_EQ(sys->pathOfWrite(3 * i), jsonPath());
        EXPECT_EQ(sys->pathOfWrite(3 * i + 1), plainPath());
        EXPECT_EQ(sys->pathOfWrite(3 * i + 2), "<stderr>");
        EXPECT_NE(sys->writes[3 * i].second.find("\"description\":\"" + msg + "\""), std::string::npos);
        EXPECT_EQ(sys->writes[3 * i + 1].second, plainLine("INFO", msg));
        EXPECT_EQ(sys->writes[3 * i + 2].second, plainLine("INFO", msg));
    }

    // Every file descriptor opened for a line is closed exactly once after its write (no leak per line)
    std::multiset<int> fileFds;
    for (const auto& [fd, data] : sys->writes)
    {
        if (fd != STDERR_FILENO)
        {
            fileFds.insert(fd);
        }
    }
    EXPECT_EQ(fileFds.size(), static_cast<std::size_t>(2 * MESSAGES));
    EXPECT_EQ(std::multiset<int>(sys->closes.begin(), sys->closes.end()), fileFds);
}

TEST_F(ManagerLogSinkTest, ConcurrentAppend)
{
    // Real system calls; only the clock and root-ness are fixed.
    ManagerLogDeps deps;
    deps.now = []()
    {
        return std::string(NOW);
    };
    deps.isRoot = []()
    {
        return false;
    };
    base::logging::initManager(options(true, true, false), deps);

    constexpr int THREADS = 8;
    constexpr int LINES = 500;
    const std::string pad(300, 'p');

    std::vector<std::thread> threads;
    for (int t = 0; t < THREADS; ++t)
    {
        threads.emplace_back(
            [t, &pad]()
            {
                for (int i = 0; i < LINES; ++i)
                {
                    base::logging::write(Level::Info,
                                         TAG,
                                         "/a/x.cpp",
                                         1,
                                         "f",
                                         "T" + std::to_string(t) + "-" + std::to_string(i) + "-" + pad);
                }
            });
    }
    // External O_APPEND writer on the same plain file (like another daemon)
    std::thread external(
        [this, &pad]()
        {
            const int fd = ::open(plainPath().c_str(), O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0660);
            ASSERT_GE(fd, 0);
            for (int i = 0; i < LINES; ++i)
            {
                const auto line = "EXT-" + std::to_string(i) + "-" + pad + "\n";
                ASSERT_EQ(::write(fd, line.data(), line.size()), static_cast<ssize_t>(line.size()));
            }
            ::close(fd);
        });
    for (auto& th : threads)
    {
        th.join();
    }
    external.join();

    std::set<std::string> expectedPlain;
    std::set<std::string> expectedJson;
    for (int t = 0; t < THREADS; ++t)
    {
        for (int i = 0; i < LINES; ++i)
        {
            const auto text = "T" + std::to_string(t) + "-" + std::to_string(i) + "-" + pad;
            auto plain = plainLine("INFO", text);
            plain.pop_back();
            expectedPlain.insert(plain);
            expectedJson.insert(std::string("{\"timestamp\":\"") + NOW + "\",\"tag\":\"" + TAG
                                + "\",\"level\":\"info\",\"description\":\"" + text + "\"}");
        }
    }
    for (int i = 0; i < LINES; ++i)
    {
        expectedPlain.insert("EXT-" + std::to_string(i) + "-" + pad);
    }

    const auto check = [](const std::string& content, std::set<std::string> expected, const char* what)
    {
        ASSERT_FALSE(content.empty()) << what;
        EXPECT_EQ(content.back(), '\n') << what;
        const auto lines = splitLines(content);
        EXPECT_EQ(lines.size(), expected.size()) << what;
        std::size_t bad = 0;
        for (const auto& line : lines)
        {
            if (expected.erase(line) != 1)
            {
                ++bad;
            }
        }
        EXPECT_EQ(bad, 0u) << what << ": split, mixed or duplicated lines";
        EXPECT_TRUE(expected.empty()) << what << ": " << expected.size() << " lines missing";
    };
    check(readFile(plainPath()), expectedPlain, "plain");
    check(readFile(jsonPath()), expectedJson, "json");
}

TEST_F(ManagerLogSinkTest, RenameBetweenWrites)
{
    ManagerLogDeps deps;
    deps.now = []()
    {
        return std::string(NOW);
    };
    deps.isRoot = []()
    {
        return false;
    };
    base::logging::initManager(options(true, false, false), deps);

    base::logging::write(Level::Info, TAG, "/a/x.cpp", 1, "f", "first line");
    const auto rotated = plainPath() + ".1";
    fs::rename(plainPath(), rotated);
    base::logging::write(Level::Info, TAG, "/a/x.cpp", 2, "f", "second line");

    EXPECT_EQ(readFile(rotated), plainLine("INFO", "first line"));
    EXPECT_EQ(readFile(plainPath()), plainLine("INFO", "second line"));
}

TEST_F(ManagerLogSinkTest, CriticalIsError)
{
    auto sys = initFake(true, true, true);

    base::logging::write(Level::Critical, TAG, "/a/x.cpp", 1, "f", "fatal-ish");
    // The process goes on and keeps logging
    base::logging::write(Level::Info, TAG, "/a/x.cpp", 2, "f", "still alive");

    EXPECT_EQ(sys->contentOf(plainPath()), plainLine("ERROR", "fatal-ish") + plainLine("INFO", "still alive"));
    EXPECT_EQ(sys->stderrContent(), plainLine("ERROR", "fatal-ish") + plainLine("INFO", "still alive"));
    EXPECT_EQ(sys->contentOf(jsonPath()),
              std::string("{\"timestamp\":\"") + NOW + "\",\"tag\":\"" + TAG
                  + "\",\"level\":\"error\",\"description\":\"fatal-ish\"}\n" + "{\"timestamp\":\"" + NOW
                  + "\",\"tag\":\"" + TAG + "\",\"level\":\"info\",\"description\":\"still alive\"}\n");
}

TEST_F(ManagerLogSinkTest, LibraryLine)
{
    auto sys = initFake(true, false, false);
    const auto libLog = logging::createStandaloneLogFunction();
    const char* libTag = "wazuh-manager-analysisd(indexer-connector)";

    // Info (1) with a 5000-byte message: the library bridge caps it at 4095 bytes
    const std::string big(5000, 'z');
    callLibrary(libLog, 1, libTag, "%s", big.c_str());
    EXPECT_EQ(sys->contentOf(plainPath()), plainLine("INFO", std::string(4095, 'z'), libTag));

    // Debug (0) and trace (5) with debug level 0: nothing is written
    const auto writesBefore = sys->writes.size();
    const auto opensBefore = sys->opens.size();
    callLibrary(libLog, 0, libTag, "library debug %d", 1);
    callLibrary(libLog, 5, libTag, "library trace %d", 1);
    EXPECT_EQ(sys->writes.size(), writesBefore);
    EXPECT_EQ(sys->opens.size(), opensBefore);

    // Level 1: the debug line is written (with the debug prefix), the trace line is not
    base::logging::setManagerDebugLevel(1);
    callLibrary(libLog, 0, libTag, "library debug %d", 2);
    callLibrary(libLog, 5, libTag, "library trace %d", 2);
    ASSERT_EQ(sys->writes.size(), writesBefore + 1);
    EXPECT_EQ(sys->writes.back().second,
              std::string(NOW) + " " + libTag
                  + "[4242] indexerConnector.cpp:77 at publish(): DEBUG: library debug 2\n");
}

TEST_F(ManagerLogSinkTest, CreateFile)
{
    const mode_t oldMask = ::umask(027);
    const auto maskBefore = procUmask();

    auto sys = std::make_shared<FakeSys>();
    sys->root = true;
    sys->gid = 42;
    auto opts = options(true, false, false);
    base::logging::initManager(opts, fakeDeps(sys));

    base::logging::write(Level::Info, TAG, "/a/x.cpp", 1, "f", "created");
    const auto maskAfter = procUmask();
    ::umask(oldMask);

    ASSERT_EQ(sys->opens.size(), 2u);
    EXPECT_EQ(sys->opens[0].path, plainPath());
    EXPECT_EQ(sys->opens[0].flags, APPEND_FLAGS);
    EXPECT_EQ(sys->opens[1].path, plainPath());
    EXPECT_EQ(sys->opens[1].flags, CREATE_FLAGS);
    EXPECT_EQ(sys->opens[1].mode, 0660u);

    ASSERT_EQ(sys->fchmods.size(), 1u);
    const int createdFd = sys->fchmods[0].first;
    EXPECT_EQ(sys->fchmods[0].second, 0660u);
    ASSERT_EQ(sys->fchowns.size(), 1u);
    EXPECT_EQ(std::get<0>(sys->fchowns[0]), createdFd);
    EXPECT_EQ(std::get<1>(sys->fchowns[0]), static_cast<uid_t>(-1));
    EXPECT_EQ(std::get<2>(sys->fchowns[0]), 42u);
    EXPECT_THAT(sys->groupQueries, ::testing::ElementsAre("wazuh-manager"));

    ASSERT_EQ(sys->writes.size(), 1u);
    EXPECT_EQ(sys->writes[0].first, createdFd);
    EXPECT_EQ(sys->writes[0].second, plainLine("INFO", "created"));

    EXPECT_FALSE(maskBefore.empty());
    EXPECT_EQ(maskBefore, maskAfter);

    // Next line: the file exists, no create/chmod/chown again
    base::logging::write(Level::Info, TAG, "/a/x.cpp", 2, "f", "appended");
    EXPECT_EQ(sys->opens.size(), 3u);
    EXPECT_EQ(sys->opens.back().flags, APPEND_FLAGS);
    EXPECT_EQ(sys->fchmods.size(), 1u);
    EXPECT_EQ(sys->fchowns.size(), 1u);
    EXPECT_EQ(sys->contentOf(plainPath()), plainLine("INFO", "created") + plainLine("INFO", "appended"));
}

TEST_F(ManagerLogSinkTest, CreateEexistRetries)
{
    auto sys = std::make_shared<FakeSys>();
    // 1st open: ENOENT; 2nd (O_CREAT|O_EXCL): another process created it meanwhile => EEXIST; 3rd: opens it.
    sys->openHook = [](const FakeSys::OpenCall&, std::size_t n) -> std::optional<int>
    {
        if (n == 1)
        {
            errno = ENOENT;
            return -1;
        }
        if (n == 2)
        {
            errno = EEXIST;
            return -1;
        }
        return 777;
    };
    base::logging::initManager(options(true, false, false), fakeDeps(sys));

    base::logging::write(Level::Info, TAG, "/a/x.cpp", 1, "f", "raced");

    ASSERT_EQ(sys->opens.size(), 3u);
    EXPECT_EQ(sys->opens[0].flags, APPEND_FLAGS);
    EXPECT_EQ(sys->opens[1].flags, CREATE_FLAGS);
    EXPECT_EQ(sys->opens[2].flags, APPEND_FLAGS);
    EXPECT_EQ(sys->opens[2].path, plainPath());
    ASSERT_EQ(sys->writes.size(), 1u);
    EXPECT_EQ(sys->writes[0].first, 777);
    EXPECT_EQ(sys->writes[0].second, plainLine("INFO", "raced"));
}

TEST_F(ManagerLogSinkTest, CreateNoGroup)
{
    auto sys = std::make_shared<FakeSys>();
    sys->root = true;
    sys->gid = std::nullopt;
    base::logging::initManager(options(true, false, false), fakeDeps(sys));

    EXPECT_NO_THROW(base::logging::write(Level::Info, TAG, "/a/x.cpp", 1, "f", "no group"));

    EXPECT_TRUE(sys->fchowns.empty());
    ASSERT_EQ(sys->fchmods.size(), 1u);
    EXPECT_EQ(sys->fchmods[0].second, 0660u);
    EXPECT_EQ(sys->contentOf(plainPath()), plainLine("INFO", "no group"));

    // Not root: no chown either, even with a group
    auto sys2 = std::make_shared<FakeSys>();
    sys2->root = false;
    sys2->gid = 42;
    auto opts = options(false, true, false);
    base::logging::initManager(opts, fakeDeps(sys2));
    base::logging::write(Level::Info, TAG, "/a/x.cpp", 1, "f", "not root");
    EXPECT_TRUE(sys2->fchowns.empty());
    EXPECT_EQ(sys2->fchmods.size(), 1u);
    EXPECT_FALSE(sys2->contentOf(jsonPath()).empty());
}

TEST_F(ManagerLogSinkTest, CreateAsRootReal)
{
    if (::getuid() != 0)
    {
        GTEST_SKIP() << "needs root";
    }
    const struct group* grp = ::getgrnam("wazuh-manager");
    if (grp == nullptr)
    {
        GTEST_SKIP() << "group wazuh-manager does not exist";
    }
    const gid_t gid = grp->gr_gid;

    const mode_t oldMask = ::umask(077); // the file must still end up 0660
    base::logging::initManager(options(true, false, false), ManagerLogDeps {});
    base::logging::write(Level::Info, TAG, "/a/x.cpp", 1, "f", "real file");
    ::umask(oldMask);

    struct stat st {};
    ASSERT_EQ(::stat(plainPath().c_str(), &st), 0);
    EXPECT_EQ(st.st_mode & 07777, 0660u);
    EXPECT_EQ(st.st_gid, gid);
    EXPECT_NE(readFile(plainPath()).find(" " + std::string(TAG) + ": INFO: real file\n"), std::string::npos);
}

TEST_F(ManagerLogSinkTest, OpenFailureIsDropped)
{
    auto stderrData = std::make_shared<std::string>();
    ManagerLogDeps deps;
    deps.now = []()
    {
        return std::string(NOW);
    };
    deps.isRoot = []()
    {
        return false;
    };
    deps.write = [stderrData](int fd, const char* data, size_t size) -> ssize_t
    {
        if (fd == STDERR_FILENO)
        {
            stderrData->append(data, size);
            return static_cast<ssize_t>(size);
        }
        return ::write(fd, data, size);
    };
    auto opts = options(true, true, true);
    const auto missingDir = m_dir / "no-such-dir";
    opts.plainPath = (missingDir / "wazuh-manager.log").string();
    base::logging::initManager(opts, deps);

    EXPECT_NO_THROW(base::logging::write(Level::Warn, TAG, "/a/x.cpp", 1, "f", "dropped in plain"));

    EXPECT_FALSE(fs::exists(missingDir));
    EXPECT_EQ(*stderrData, plainLine("WARNING", "dropped in plain"));
    EXPECT_EQ(readFile(jsonPath()),
              std::string("{\"timestamp\":\"") + NOW + "\",\"tag\":\"" + TAG
                  + "\",\"level\":\"warning\",\"description\":\"dropped in plain\"}\n");
}

// ---------------------------------------------------------------------------------------------------------------------
// Manager home (oracle: brief-contrato §4)
// ---------------------------------------------------------------------------------------------------------------------

namespace
{
const char* const HOME_NOT_FOUND = "(1108): Unable to find Wazuh install directory. Export it to WAZUH_MANAGER_HOME "
                                   "environment variable.";

class ManagerHome : public ::testing::Test
{
protected:
    fs::path m_dir;
    fs::path m_oldCwd;
    std::map<std::string, std::string> m_env;
    std::vector<std::string> m_dirQueries;

    void SetUp() override
    {
        m_dir = caseDir();
        fs::remove_all(m_dir);
        fs::create_directories(m_dir / "logs");
        m_oldCwd = fs::current_path();
        fs::current_path(m_dir);
    }

    void TearDown() override
    {
        fs::current_path(m_oldCwd);
        fs::remove_all(m_dir);
    }

    fs::path resolve(const std::string& exePath)
    {
        return base::process::resolveManagerHome(
            [this](const char* name) -> const char*
            {
                auto it = m_env.find(name);
                return it == m_env.end() ? nullptr : it->second.c_str();
            },
            exePath,
            [this](const std::string& path)
            {
                m_dirQueries.push_back(path);
                std::error_code ec;
                return !path.empty() && fs::is_directory(path, ec);
            });
    }

    std::string dir(const std::string& rel) const
    {
        fs::create_directories(m_dir / rel);
        return (m_dir / rel).string();
    }

    /// The exit path: rc 1 and exactly one CRITICAL line on stderr (no log file, even with an active sink).
    void expectExit(const std::string& exePath)
    {
        ::testing::FLAGS_gtest_death_test_style = "threadsafe";
        const auto logDir = m_dir / "logs";
        const std::regex line("^[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} wazuh-manager-analysisd: "
                              "CRITICAL: \\(1108\\): Unable to find Wazuh install directory\\. Export it to "
                              "WAZUH_MANAGER_HOME environment variable\\.\n$");
        EXPECT_EXIT(
            {
                ManagerLogOptions opts;
                opts.plainPath = (logDir / "wazuh-manager.log").string();
                opts.jsonPath = (logDir / "wazuh-manager.json").string();
                opts.logJson = true;
                opts.writeStderr = false;
                base::logging::initManager(opts);
                resolve(exePath);
                std::_Exit(0);
            },
            ::testing::ExitedWithCode(1),
            ::testing::Truly([&line](const std::string& err) { return std::regex_match(err, line); }));
        EXPECT_TRUE(fs::is_empty(logDir)) << "the home error must not be written to a log file";
    }
};
} // namespace

TEST_F(ManagerHome, ForceHomeAsIs)
{
    m_env["WAZUH_MANAGER_FORCE_HOME"] = "/no/such/home/bin/x";
    m_env["WAZUH_MANAGER_HOME"] = dir("other");
    EXPECT_EQ(resolve(dir("h/bin") + "/wazuh-manager-analysisd"), fs::path("/no/such/home/bin/x"));
    EXPECT_TRUE(m_dirQueries.empty()) << "a forced home is never checked";
}

TEST_F(ManagerHome, ForceHomeEmpty)
{
    m_env["WAZUH_MANAGER_FORCE_HOME"] = "";
    EXPECT_EQ(resolve(dir("h/bin") + "/wazuh-manager-analysisd"), fs::path(""));
    EXPECT_TRUE(m_dirQueries.empty());
}

TEST_F(ManagerHome, ManagerHomeEnvAsIs)
{
    const auto home = dir("custom/bin/inside");
    m_env["WAZUH_MANAGER_HOME"] = home;
    EXPECT_EQ(resolve(dir("h/bin") + "/wazuh-manager-analysisd"), fs::path(home));
}

TEST_F(ManagerHome, ManagerHomeEnvEmptyUsesExe)
{
    m_env["WAZUH_MANAGER_HOME"] = "";
    EXPECT_EQ(resolve(dir("h/bin") + "/wazuh-manager-analysisd"), fs::path(m_dir / "h"));
}

TEST_F(ManagerHome, ManagerHomeEnvNotDirectoryExits)
{
    m_env["WAZUH_MANAGER_HOME"] = (m_dir / "missing").string();
    expectExit(dir("h/bin") + "/wazuh-manager-analysisd");
}

TEST_F(ManagerHome, ExeCutAtFirstBin)
{
    EXPECT_EQ(resolve(dir("h/bin") + "/wazuh-manager-analysisd"), fs::path(m_dir / "h"));
    dir("x/bin/y/bin");
    EXPECT_EQ(resolve((m_dir / "x/bin/y/bin/wazuh-manager-analysisd").string()), fs::path(m_dir / "x"));
}

TEST_F(ManagerHome, ExeBinariesSubstring)
{
    // "/bin" is a substring of "/binaries": the cut happens there (binary-copy case of the golden)
    dir("binaries/x/bin");
    EXPECT_EQ(resolve((m_dir / "binaries/x/bin/x").string()), fs::path(m_dir));
}

TEST_F(ManagerHome, ExeWithoutBin)
{
    dir("plain/sub");
    EXPECT_EQ(resolve((m_dir / "plain/sub/wazuh-manager-analysisd").string()), fs::path(m_dir / "plain/sub"));
}

TEST_F(ManagerHome, ExeNotDirectoryExits)
{
    expectExit((m_dir / "gone/bin/wazuh-manager-analysisd").string());
}

TEST_F(ManagerHome, NoManagerModeIsCurrentPath)
{
    EXPECT_EQ(base::process::getWazuhHome(), fs::current_path());
    EXPECT_EQ(base::process::getWazuhHome(), m_dir);
}

TEST_F(ManagerHome, ManagerModeResolvesOnce)
{
    ::testing::FLAGS_gtest_death_test_style = "threadsafe";
    const auto forced = (m_dir / "forced-home").string();
    EXPECT_EXIT(
        {
            ::setenv("WAZUH_MANAGER_FORCE_HOME", forced.c_str(), 1);
            base::process::setManagerMode();
            if (base::process::getWazuhHome() != fs::path(forced))
            {
                std::_Exit(2);
            }
            // Cached: a later change of the environment is not seen
            ::setenv("WAZUH_MANAGER_FORCE_HOME", "/elsewhere", 1);
            std::_Exit(base::process::getWazuhHome() == fs::path(forced) ? 0 : 3);
        },
        ::testing::ExitedWithCode(0),
        "");
}
