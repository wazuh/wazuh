// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <climits>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <limits>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

#include <openssl/rand.h>

#include <base/utils/generator.hpp>
#include <base/utils/timeUtils.hpp>

using namespace base::utils::generators;

TEST(GeneratorTest, GenerateUUIDv4Format)
{
    const auto uuid = generateUUIDv4();

    ASSERT_EQ(uuid.size(), UUID_V4_LENGTH);
    EXPECT_EQ(uuid[8], '-');
    EXPECT_EQ(uuid[13], '-');
    EXPECT_EQ(uuid[18], '-');
    EXPECT_EQ(uuid[23], '-');
    EXPECT_EQ(uuid[14], '4');
    EXPECT_TRUE(uuid[19] == '8' || uuid[19] == '9' || uuid[19] == 'a' || uuid[19] == 'b');

    for (size_t i = 0; i < uuid.size(); ++i)
    {
        if (i == 8 || i == 13 || i == 18 || i == 23)
        {
            continue;
        }
        EXPECT_TRUE(std::isxdigit(static_cast<unsigned char>(uuid[i]))) << "at index " << i;
    }
}

TEST(GeneratorTest, GenerateUUIDv4IsUnique)
{
    std::set<std::string> uuids;
    for (size_t i = 0; i < 1000; ++i)
    {
        uuids.insert(generateUUIDv4());
    }

    EXPECT_EQ(uuids.size(), 1000U);
}

TEST(GeneratorTest, IsValidResourceIdRejectsEmpty)
{
    EXPECT_FALSE(isValidResourceId(""));
}

TEST(GeneratorTest, IsValidResourceIdAcceptsAnyUUIDVersion)
{
    // Identifiers are opaque to the engine, the version and variant are never interpreted
    EXPECT_TRUE(isValidResourceId(generateUUIDv4()));
    EXPECT_TRUE(isValidResourceId("6093809a-6285-5cf8-9284-63bd68f796e9")); // v5
    EXPECT_TRUE(isValidResourceId("0199a9f4-1b1e-7c3b-8f2a-2f9a1c0d4e5f")); // v7
    EXPECT_TRUE(isValidResourceId("00000000-0000-0000-0000-000000000000")); // nil
    EXPECT_TRUE(isValidResourceId("6093809A-6285-5CF8-9284-63BD68F796E9")); // uppercase
}

TEST(GeneratorTest, IsValidResourceIdAcceptsNonUUIDIdentifiers)
{
    EXPECT_TRUE(isValidResourceId("not-a-uuid"));
    EXPECT_TRUE(isValidResourceId("decoder/windows/0"));
    EXPECT_TRUE(isValidResourceId("0"));
    EXPECT_TRUE(isValidResourceId("with space"));
    EXPECT_TRUE(isValidResourceId("MixedCase-Id_1.2"));
    EXPECT_TRUE(isValidResourceId("identificador-ñ-日本"));                   // UTF-8 is not a control character
    EXPECT_TRUE(isValidResourceId(std::string(MAX_RESOURCE_ID_LENGTH, 'a'))); // exactly at the limit
}

TEST(GeneratorTest, IsValidResourceIdRejectsControlCharacters)
{
    EXPECT_FALSE(isValidResourceId("bad\nid"));
    EXPECT_FALSE(isValidResourceId("bad\tid"));
    EXPECT_FALSE(isValidResourceId("bad\rid"));
    EXPECT_FALSE(isValidResourceId(std::string("bad\0id", 6)));
    EXPECT_FALSE(isValidResourceId("bad\x1bid")); // ESC
    EXPECT_FALSE(isValidResourceId("bad\x7fid")); // DEL
    EXPECT_FALSE(isValidResourceId("\n"));
}

TEST(GeneratorTest, IsValidResourceIdRejectsOversizedIdentifiers)
{
    EXPECT_FALSE(isValidResourceId(std::string(MAX_RESOURCE_ID_LENGTH + 1, 'a')));
    EXPECT_FALSE(isValidResourceId(std::string(4096, 'a')));
}

TEST(GeneratorTest, RandomHexStringLength)
{
    EXPECT_TRUE(randomHexString(0).empty());

    const auto hex = randomHexString(16);
    ASSERT_EQ(hex.size(), 16U);
    for (const auto c : hex)
    {
        EXPECT_TRUE(std::isxdigit(static_cast<unsigned char>(c)));
    }
}

/***************************
 * Random source, UUIDv4 and document identifier tests
 ***************************/

namespace
{
namespace detail = base::utils::generators::detail;

// Restores the previous random source when the test ends, whatever the outcome.
class RandSourceGuard
{
public:
    explicit RandSourceGuard(detail::RandBytesFn fn)
        : m_previous(detail::exchangeRandBytesForTesting(fn))
    {
    }

    ~RandSourceGuard() { detail::exchangeRandBytesForTesting(m_previous); }

    RandSourceGuard(const RandSourceGuard&) = delete;
    RandSourceGuard& operator=(const RandSourceGuard&) = delete;

private:
    detail::RandBytesFn m_previous;
};

// State shared by the fake sources (reset by each test before installing its fake).
std::atomic<int> g_fakeCalls {0};
std::mutex g_fakeSizesMutex;
std::vector<int> g_fakeSizes;

void resetFakeState()
{
    g_fakeCalls.store(0);
    std::lock_guard<std::mutex> lock(g_fakeSizesMutex);
    g_fakeSizes.clear();
}

std::vector<int> fakeSizes()
{
    std::lock_guard<std::mutex> lock(g_fakeSizesMutex);
    return g_fakeSizes;
}

int recordCall(int n)
{
    {
        std::lock_guard<std::mutex> lock(g_fakeSizesMutex);
        g_fakeSizes.push_back(n);
    }
    return g_fakeCalls.fetch_add(1);
}

// 1st call: 00 01 02 ...; later calls: ff ff ...
int fakeSequentialThenOnes(unsigned char* buf, int n)
{
    const auto call = recordCall(n);
    for (int i = 0; i < n; ++i)
    {
        buf[i] = call == 0 ? static_cast<unsigned char>(i) : 0xff;
    }
    return 1;
}

// Every byte of the k-th call (1-based) is k.
int fakeCounter(unsigned char* buf, int n)
{
    const auto call = recordCall(n);
    std::memset(buf, call + 1, static_cast<size_t>(n));
    return 1;
}

// Counts the call and reports success without writing (lets a test ask for sizes it could not allocate).
int fakeCounterNoWrite(unsigned char* /*buf*/, int n)
{
    recordCall(n);
    return 1;
}

// Always fails, as RAND_bytes does when the DRBG cannot be seeded.
int fakeFailure(unsigned char* /*buf*/, int n)
{
    recordCall(n);
    return 0;
}

constexpr std::array<uint8_t, DOC_ID_PREFIX_SIZE> KNOWN_PREFIX {
    0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x01, 0x23, 0x45, 0x67};

// 1st call: writes 5 bytes and fails; later calls: KNOWN_PREFIX (when 12 bytes are asked).
int fakePartialFailureThenKnown(unsigned char* buf, int n)
{
    const auto call = recordCall(n);
    if (call == 0)
    {
        std::memset(buf, 0xee, static_cast<size_t>(std::min(n, 5)));
        return 0;
    }
    for (int i = 0; i < n; ++i)
    {
        buf[i] = KNOWN_PREFIX[static_cast<size_t>(i) % KNOWN_PREFIX.size()];
    }
    return 1;
}

// Unpadded base64url decoder (RFC 4648 §5), independent from the production encoder.
std::optional<std::vector<uint8_t>> decodeBase64Url(const std::string& in)
{
    auto value = [](char c) -> int
    {
        if (c >= 'A' && c <= 'Z')
            return c - 'A';
        if (c >= 'a' && c <= 'z')
            return c - 'a' + 26;
        if (c >= '0' && c <= '9')
            return c - '0' + 52;
        if (c == '-')
            return 62;
        if (c == '_')
            return 63;
        return -1;
    };

    if (in.size() % 4 == 1)
    {
        return std::nullopt;
    }

    std::vector<uint8_t> out;
    uint32_t acc = 0;
    int bits = 0;
    for (const auto c : in)
    {
        const auto v = value(c);
        if (v < 0)
        {
            return std::nullopt;
        }
        acc = (acc << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8)
        {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((acc >> bits) & 0xff));
        }
    }
    // Unused trailing bits must be zero (canonical encoding)
    if (bits > 0 && (acc & ((1u << bits) - 1)) != 0)
    {
        return std::nullopt;
    }
    return out;
}

constexpr size_t DOC_ID_BYTES = 20;

// Big-endian clock of bytes 0-7 of a decoded identifier.
int64_t docIdClock(const std::vector<uint8_t>& raw)
{
    uint64_t v = 0;
    for (size_t i = 0; i < 8; ++i)
    {
        v = (v << 8) | raw[i];
    }
    return static_cast<int64_t>(v);
}

// Random prefix of bytes 8-19 of a decoded identifier.
std::vector<uint8_t> docIdPrefix(const std::vector<uint8_t>& raw)
{
    return std::vector<uint8_t>(raw.begin() + 8, raw.begin() + DOC_ID_BYTES);
}

// Prefix of an identifier, empty when it does not decode to 20 bytes.
std::vector<uint8_t> prefixOf(const std::string& id)
{
    const auto raw = decodeBase64Url(id);
    if (!raw || raw->size() != DOC_ID_BYTES)
    {
        return {};
    }
    return docIdPrefix(*raw);
}

bool isWellFormedDocId(const std::string& id)
{
    if (id.size() != DOC_ID_LENGTH)
    {
        return false;
    }
    const auto alphabet = [](unsigned char c)
    {
        return std::isalnum(c) || c == '-' || c == '_';
    };
    if (!std::all_of(id.begin(), id.end(), alphabet))
    {
        return false;
    }
    const auto raw = decodeBase64Url(id);
    return raw && raw->size() == DOC_ID_BYTES;
}

// Waits for a child with a timeout (10 s); kills it when the timeout expires. Returns the wait status.
std::optional<int> waitChild(pid_t pid)
{
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (std::chrono::steady_clock::now() < deadline)
    {
        int status = 0;
        const auto r = ::waitpid(pid, &status, WNOHANG);
        if (r == pid)
        {
            return status;
        }
        if (r < 0 && errno != EINTR)
        {
            return std::nullopt;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    ::kill(pid, SIGKILL);
    int status = 0;
    ::waitpid(pid, &status, 0);
    return std::nullopt;
}

bool exitedOk(const std::optional<int>& status)
{
    return status && WIFEXITED(*status) && WEXITSTATUS(*status) == 0;
}

// Writes one identifier and a newline (a single write, below PIPE_BUF, so it is atomic).
bool writeLine(int fd, const std::string& line)
{
    const auto data = line + "\n";
    return ::write(fd, data.data(), data.size()) == static_cast<ssize_t>(data.size());
}

// Reads everything the (already exited) writers left in the pipe, without blocking.
std::vector<std::string> readLines(int fd)
{
    ::fcntl(fd, F_SETFL, ::fcntl(fd, F_GETFL) | O_NONBLOCK);
    std::string all;
    char buf[256];
    while (true)
    {
        const auto r = ::read(fd, buf, sizeof(buf));
        if (r > 0)
        {
            all.append(buf, static_cast<size_t>(r));
            continue;
        }
        if (r < 0 && errno == EINTR)
        {
            continue;
        }
        break;
    }
    std::vector<std::string> lines;
    std::istringstream ss(all);
    std::string line;
    while (std::getline(ss, line))
    {
        lines.push_back(line);
    }
    return lines;
}

// Generates one identifier in a child process context; never throws.
std::string safeGenerateDocId()
{
    try
    {
        return generateDocId();
    }
    catch (...)
    {
        return {};
    }
}

constexpr size_t THREADS = 16;
constexpr size_t IDS_PER_THREAD = 100000;
} // namespace

TEST(GeneratorTest, UUIDv4UsesRandBytes)
{
    resetFakeState();
    RandSourceGuard guard(&fakeSequentialThenOnes);

    EXPECT_EQ(generateUUIDv4(), "00010203-0405-4607-8809-0a0b0c0d0e0f");
    EXPECT_EQ(fakeSizes(), std::vector<int>({16}));

    EXPECT_EQ(generateUUIDv4(), "ffffffff-ffff-4fff-bfff-ffffffffffff");
    EXPECT_EQ(fakeSizes(), std::vector<int>({16, 16}));
}

TEST(GeneratorTest, UUIDv4FreshEntropyPerId)
{
    resetFakeState();
    RandSourceGuard guard(&fakeCounter);

    std::set<std::string> ids;
    for (int i = 0; i < 3; ++i)
    {
        ids.insert(generateUUIDv4());
    }

    EXPECT_EQ(g_fakeCalls.load(), 3);
    EXPECT_EQ(ids.size(), 3U);
}

TEST(GeneratorTest, RandBytesFailureThrows)
{
    resetFakeState();
    RandSourceGuard guard(&fakeFailure);

    EXPECT_THROW(generateUUIDv4(), std::runtime_error);

    // generateDocId() keeps per-thread state: a new thread has not drawn its prefix yet
    std::atomic<bool> threwRuntimeError {false};
    std::atomic<bool> threwOther {false};
    std::thread t(
        [&]()
        {
            try
            {
                generateDocId();
            }
            catch (const std::runtime_error&)
            {
                threwRuntimeError.store(true);
            }
            catch (...)
            {
                threwOther.store(true);
            }
        });
    t.join();

    EXPECT_TRUE(threwRuntimeError.load());
    EXPECT_FALSE(threwOther.load());
}

TEST(GeneratorTest, FillRandomRejectsOversize)
{
    resetFakeState();
    RandSourceGuard guard(&fakeCounter);

    uint8_t buf[1] {};
    EXPECT_THROW(fillRandom(buf, static_cast<size_t>(INT_MAX) + 1), std::runtime_error);
    EXPECT_EQ(g_fakeCalls.load(), 0);
}

TEST(GeneratorTest, FillRandomZeroIsNoop)
{
    resetFakeState();
    RandSourceGuard guard(&fakeCounter);

    // nullptr is allowed only when n is 0, and the source is not consulted
    EXPECT_NO_THROW(fillRandom(nullptr, 0));
    EXPECT_EQ(g_fakeCalls.load(), 0);
}

TEST(GeneratorTest, FillRandomAcceptsIntMax)
{
    resetFakeState();
    RandSourceGuard guard(&fakeCounterNoWrite);

    // INT_MAX is the largest accepted size: it reaches the source unchanged (the fake writes nothing)
    EXPECT_NO_THROW(fillRandom(nullptr, static_cast<size_t>(INT_MAX)));
    EXPECT_EQ(g_fakeCalls.load(), 1);
    const auto sizes = fakeSizes();
    ASSERT_EQ(sizes.size(), 1U);
    EXPECT_EQ(sizes[0], INT_MAX);
}

TEST(GeneratorTest, DefaultSourceIsRandBytes)
{
    const detail::RandBytesFn randBytes = &RAND_bytes;

    // Restore the default and get the source that was active (the default one: no fake is installed)
    EXPECT_EQ(detail::exchangeRandBytesForTesting(nullptr), randBytes);

    // Installing a fake returns the default, restoring returns the fake
    EXPECT_EQ(detail::exchangeRandBytesForTesting(&fakeCounter), randBytes);
    EXPECT_EQ(detail::exchangeRandBytesForTesting(nullptr), &fakeCounter);

    // After restoring, the active source is RAND_bytes again
    EXPECT_EQ(detail::exchangeRandBytesForTesting(nullptr), randBytes);
}

TEST(GeneratorTest, UUIDv4UniqueAcrossThreads)
{
    std::vector<std::unordered_set<std::string>> perThread(THREADS);
    std::vector<std::thread> threads;
    for (size_t t = 0; t < THREADS; ++t)
    {
        threads.emplace_back(
            [&perThread, t]()
            {
                auto& ids = perThread[t];
                ids.reserve(IDS_PER_THREAD);
                for (size_t i = 0; i < IDS_PER_THREAD; ++i)
                {
                    ids.insert(generateUUIDv4());
                }
            });
    }
    for (auto& t : threads)
    {
        t.join();
    }

    std::unordered_set<std::string> all;
    all.reserve(THREADS * IDS_PER_THREAD);
    for (auto& ids : perThread)
    {
        EXPECT_EQ(ids.size(), IDS_PER_THREAD);
        all.merge(ids);
    }
    EXPECT_EQ(all.size(), THREADS * IDS_PER_THREAD);
}

TEST(GeneratorTest, DocIdVectors)
{
    // Two cases shared with the benchmark that chose the id algorithm (same inputs, same expected ids).
    // rand_hex: the first 12 bytes are the prefix; clock[]: nanoseconds; expect[]: unpadded base64url.
    struct Case
    {
        const char* name;
        std::array<uint8_t, DOC_ID_PREFIX_SIZE> prefix;
        std::vector<int64_t> clock;
        std::vector<std::string> expect;
    };

    const std::vector<int64_t> clock {1760000000123456789LL,
                                      1760000000123456789LL,
                                      1760000000123456790LL,
                                      1760000000122456789LL,
                                      1760001000123456789LL};

    const std::vector<Case> cases {
        {"5bt-proc0",
         {0xf1, 0xeb, 0x40, 0xee, 0xef, 0xe8, 0xac, 0xa5, 0x5e, 0x87, 0xc8, 0x0e},
         clock,
         {"GGzGrNwLzRXx60Du7-ispV6HyA4",
          "GGzGrNwLzRbx60Du7-ispV6HyA4",
          "GGzGrNwLzRfx60Du7-ispV6HyA4",
          "GGzGrNwLzRjx60Du7-ispV6HyA4",
          "GGzHlbCw3RXx60Du7-ispV6HyA4"}},
        {"5bt-proc1",
         {0x88, 0x60, 0x64, 0x6b, 0x40, 0xf1, 0x7b, 0x10, 0xcf, 0xcb, 0x90, 0xa2},
         clock,
         {"GGzGrNwLzRWIYGRrQPF7EM_LkKI",
          "GGzGrNwLzRaIYGRrQPF7EM_LkKI",
          "GGzGrNwLzReIYGRrQPF7EM_LkKI",
          "GGzGrNwLzRiIYGRrQPF7EM_LkKI",
          "GGzHlbCw3RWIYGRrQPF7EM_LkKI"}},
    };

    for (const auto& c : cases)
    {
        detail::DocIdGenerator gen(c.prefix);
        ASSERT_EQ(c.clock.size(), c.expect.size()) << c.name;
        for (size_t i = 0; i < c.clock.size(); ++i)
        {
            EXPECT_EQ(gen.next(c.clock[i]), c.expect[i]) << c.name << " id " << i;
        }
    }
}

TEST(GeneratorTest, DocIdClockSaturatesAtInt64Max)
{
    // At INT64_MAX the clock cannot advance: it saturates (the value repeats) instead of overflowing
    constexpr auto maxClock = std::numeric_limits<int64_t>::max();
    detail::DocIdGenerator gen(KNOWN_PREFIX);
    const auto first = gen.next(maxClock);
    const auto second = gen.next(maxClock);

    const std::vector<uint8_t> known(KNOWN_PREFIX.begin(), KNOWN_PREFIX.end());
    for (const auto& id : {first, second})
    {
        ASSERT_TRUE(isWellFormedDocId(id)) << id;
        const auto raw = decodeBase64Url(id);
        ASSERT_TRUE(raw.has_value()) << id;
        EXPECT_EQ(docIdClock(*raw), maxClock) << id;
        EXPECT_EQ(docIdPrefix(*raw), known) << id;
    }
}

TEST(GeneratorTest, DocIdFormat)
{
    for (size_t i = 0; i < 10000; ++i)
    {
        const auto id = generateDocId();
        ASSERT_EQ(id.size(), DOC_ID_LENGTH) << id;
        ASSERT_TRUE(isWellFormedDocId(id)) << id;
        ASSERT_TRUE(isValidResourceId(id)) << id;
    }
}

TEST(GeneratorTest, DocIdPrefixLifecycle)
{
    resetFakeState();
    RandSourceGuard guard(&fakePartialFailureThenKnown);

    // A new thread, so that the prefix of this thread has not been drawn yet
    int64_t before = 0;
    int64_t after = 0;
    bool firstThrew = false;
    bool firstThrewOther = false;
    int callsAfterFailure = -1;
    std::vector<std::string> ids;
    std::thread t(
        [&]()
        {
            before = base::utils::time::systemEpochNanos();
            try
            {
                generateDocId();
            }
            catch (const std::runtime_error&)
            {
                firstThrew = true;
            }
            catch (...)
            {
                firstThrewOther = true;
            }
            callsAfterFailure = g_fakeCalls.load();
            try
            {
                for (int i = 0; i < 100; ++i)
                {
                    ids.push_back(generateDocId());
                }
            }
            catch (...)
            {
            }
            after = base::utils::time::systemEpochNanos();
        });
    t.join();

    EXPECT_TRUE(firstThrew);
    EXPECT_FALSE(firstThrewOther);
    EXPECT_EQ(callsAfterFailure, 1);

    // Exactly one more call, of 12 bytes, for the 100 identifiers
    EXPECT_EQ(g_fakeCalls.load(), 2);
    const auto sizes = fakeSizes();
    ASSERT_EQ(sizes.size(), 2U);
    EXPECT_EQ(sizes[1], static_cast<int>(DOC_ID_PREFIX_SIZE));

    ASSERT_EQ(ids.size(), 100U);
    const std::vector<uint8_t> known(KNOWN_PREFIX.begin(), KNOWN_PREFIX.end());
    for (const auto& id : ids)
    {
        ASSERT_TRUE(isWellFormedDocId(id)) << id;
        const auto raw = decodeBase64Url(id);
        EXPECT_EQ(docIdPrefix(*raw), known) << id;
        EXPECT_GE(docIdClock(*raw), before) << id;
        EXPECT_LE(docIdClock(*raw), after) << id;
    }
}

TEST(GeneratorTest, DocIdStrictlyIncreasingPerThread)
{
    int64_t last = std::numeric_limits<int64_t>::min();
    for (size_t i = 0; i < 100000; ++i)
    {
        const auto id = generateDocId();
        const auto raw = decodeBase64Url(id);
        ASSERT_TRUE(raw && raw->size() == DOC_ID_BYTES) << id;
        const auto clock = docIdClock(*raw);
        ASSERT_GT(clock, last) << "id " << i << ": " << id;
        last = clock;
    }
}

TEST(GeneratorTest, DocIdUniqueAcrossThreads)
{
    std::vector<std::unordered_set<std::string>> perThread(THREADS);
    std::vector<std::thread> threads;
    for (size_t t = 0; t < THREADS; ++t)
    {
        threads.emplace_back(
            [&perThread, t]()
            {
                auto& ids = perThread[t];
                ids.reserve(IDS_PER_THREAD);
                for (size_t i = 0; i < IDS_PER_THREAD; ++i)
                {
                    ids.insert(generateDocId());
                }
            });
    }
    for (auto& t : threads)
    {
        t.join();
    }

    std::set<std::vector<uint8_t>> prefixes;
    std::unordered_set<std::string> all;
    all.reserve(THREADS * IDS_PER_THREAD);
    for (auto& ids : perThread)
    {
        ASSERT_EQ(ids.size(), IDS_PER_THREAD);
        const auto prefix = prefixOf(*ids.begin());
        ASSERT_EQ(prefix.size(), DOC_ID_PREFIX_SIZE);
        prefixes.insert(prefix);
        all.merge(ids);
    }
    EXPECT_EQ(all.size(), THREADS * IDS_PER_THREAD);
    EXPECT_EQ(prefixes.size(), THREADS);
}

TEST(GeneratorTest, DocIdNewPrefixAfterFork)
{
    // No other thread of this test is alive here: the ones of previous tests were joined
    const auto parentId = generateDocId();
    const auto parentPrefix = prefixOf(parentId);
    ASSERT_EQ(parentPrefix.size(), DOC_ID_PREFIX_SIZE) << parentId;

    int fds[2];
    ASSERT_EQ(::pipe(fds), 0);

    const pid_t child = ::fork();
    ASSERT_NE(child, -1);
    if (child == 0)
    {
        // Child: generates, forks a grandchild that generates too, and waits for it
        ::close(fds[0]);
        const auto childId = safeGenerateDocId();
        if (childId.empty() || !writeLine(fds[1], childId))
        {
            ::_exit(1);
        }

        const pid_t grandchild = ::fork();
        if (grandchild == -1)
        {
            ::_exit(1);
        }
        if (grandchild == 0)
        {
            const auto grandchildId = safeGenerateDocId();
            ::_exit(!grandchildId.empty() && writeLine(fds[1], grandchildId) ? 0 : 1);
        }
        ::_exit(exitedOk(waitChild(grandchild)) ? 0 : 1);
    }

    ::close(fds[1]);
    const auto status = waitChild(child);
    const auto lines = readLines(fds[0]);
    ::close(fds[0]);

    ASSERT_TRUE(exitedOk(status)) << "child failed or timed out";
    ASSERT_EQ(lines.size(), 2U);

    const auto& childId = lines[0];
    const auto& grandchildId = lines[1];
    ASSERT_TRUE(isWellFormedDocId(childId)) << childId;
    ASSERT_TRUE(isWellFormedDocId(grandchildId)) << grandchildId;

    const auto childPrefix = prefixOf(childId);
    const auto grandchildPrefix = prefixOf(grandchildId);
    EXPECT_NE(childPrefix, parentPrefix);
    EXPECT_NE(grandchildPrefix, parentPrefix);
    EXPECT_NE(grandchildPrefix, childPrefix);

    // The parent keeps its own prefix
    EXPECT_EQ(prefixOf(generateDocId()), parentPrefix);
}

/*
 * What this proves: a fork() issued from a thread that never generated (while another thread of the process did)
 * gives the child a valid identifier whose prefix differs from the worker's, and the fork handler does not crash on
 * the uninitialized thread-local state of the forking thread.
 * What it does not prove: removing the fork handler goes unnoticed here, because the state is thread_local and the
 * forking thread never shared the worker's prefix; DocIdNewPrefixAfterFork covers the handler.
 */
TEST(GeneratorTest, DocIdForkFromThreadWithoutState)
{
    int fds[2];
    ASSERT_EQ(::pipe(fds), 0);

    // Fresh auxiliary process, forked while this test has no thread alive, so the scenario does not depend on the
    // order in which gtest runs the tests
    const pid_t helper = ::fork();
    ASSERT_NE(helper, -1);
    if (helper == 0)
    {
        ::close(fds[0]);

        // A worker generates and ends
        std::string workerId;
        std::thread worker([&workerId]() { workerId = safeGenerateDocId(); });
        worker.join();
        if (workerId.empty() || !writeLine(fds[1], workerId))
        {
            ::_exit(1);
        }

        // The main thread, which did not generate here, forks; the grandchild generates
        const pid_t grandchild = ::fork();
        if (grandchild == -1)
        {
            ::_exit(1);
        }
        if (grandchild == 0)
        {
            const auto grandchildId = safeGenerateDocId();
            ::_exit(!grandchildId.empty() && writeLine(fds[1], grandchildId) ? 0 : 1);
        }
        ::_exit(exitedOk(waitChild(grandchild)) ? 0 : 1);
    }

    ::close(fds[1]);
    const auto status = waitChild(helper);
    const auto lines = readLines(fds[0]);
    ::close(fds[0]);

    ASSERT_TRUE(exitedOk(status)) << "auxiliary process failed or timed out";
    ASSERT_EQ(lines.size(), 2U);

    const auto& workerId = lines[0];
    const auto& grandchildId = lines[1];
    ASSERT_TRUE(isWellFormedDocId(workerId)) << workerId;
    ASSERT_TRUE(isWellFormedDocId(grandchildId)) << grandchildId;
    EXPECT_TRUE(isValidResourceId(grandchildId));
    EXPECT_NE(prefixOf(grandchildId), prefixOf(workerId));
}
