/*
 * Wazuh indexer client
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _INDEXER_CLIENT_TESTS_COMPONENT_WRITE_FIXTURE_HPP
#define _INDEXER_CLIENT_TESTS_COMPONENT_WRITE_FIXTURE_HPP

// Shared by the write component suites: the runtime fixture, a programmable sink installed
// through WritePath::setSink, a callback result log and op/spec builders. Every wait is bounded; every case ends with
// the charge and the retained ops at 0 (checked in TearDown through the write path, which the fixture keeps alive).

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "componentFixture.hpp"
#include "indexer_client/runtime.hpp"
#include "runtime/runtimeInternal.hpp"
#include "testing/hooks.hpp"
#include "write/bucket.hpp"
#include "write/encoding.hpp"
#include "write/sink.hpp"
#include "write/writer.hpp"

namespace write_component
{
    using namespace std::chrono_literals;
    namespace ic = indexer_client;
    namespace wr = indexer_client::detail::write;

    inline ic::TimePoint now()
    {
        return std::chrono::steady_clock::now();
    }

    /// What the sink saw of one dispatch.
    struct DispatchRecord final
    {
        std::string bucket;
        std::uint64_t bytes {0};
        std::size_t ops {0};
        ic::TimePoint at {};
    };

    /// The test sink: a programmable capacity (UNLIMITED, or a number of batches that each dispatch consumes), and
    /// either holds every batch for the test to resolve (Hold) or resolves every op Ok on dispatch (ResolveOk).
    class TestSink final : public wr::BatchSink
    {
    public:
        static constexpr std::size_t UNLIMITED = std::numeric_limits<std::size_t>::max();

        enum class Mode
        {
            Hold,
            ResolveOk
        };

        TestSink(std::weak_ptr<wr::WritePath> path, Mode mode, std::size_t capacity)
            : m_path(std::move(path))
            , m_mode(mode)
            , m_capacity(capacity)
        {
        }

        std::size_t capacity() override
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_capacity;
        }

        void dispatch(wr::Batch batch) override
        {
            std::vector<std::shared_ptr<wr::OpState>> resolveNow;
            std::shared_ptr<wr::Bucket> bucket = batch.bucket; // resolve() takes the op's bucket.
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                if (m_capacity != UNLIMITED && m_capacity > 0)
                {
                    --m_capacity;
                }
                if (m_stopped)
                {
                    ++m_afterStop;
                }
                m_log.push_back(DispatchRecord {
                    batch.bucket ? batch.bucket->spec().name : std::string(), batch.bytes, batch.ops.size(), now()});
                if (m_mode == Mode::Hold)
                {
                    m_held.push_back(std::move(batch));
                }
                else
                {
                    resolveNow = std::move(batch.ops);
                }
            }
            m_cv.notify_all();
            if (!resolveNow.empty())
            {
                if (auto path = m_path.lock())
                {
                    for (const auto& op : resolveNow)
                    {
                        path->resolve(bucket, op, ok());
                    }
                }
            }
        }

        void stop() override
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_stopped = true;
        }

        /// Sets the capacity and tells the scheduler (WritePath::sinkReady).
        void grant(std::size_t capacity)
        {
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_capacity = capacity;
            }
            if (auto path = m_path.lock())
            {
                path->sinkReady();
            }
        }

        void setCapacity(std::size_t capacity)
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_capacity = capacity;
        }

        /// Waits until `count` batches were dispatched in total.
        bool waitDispatched(std::size_t count, std::chrono::milliseconds timeout = 5s)
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            return m_cv.wait_for(lock, timeout, [&] { return m_log.size() >= count; });
        }

        std::size_t dispatched() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_log.size();
        }

        std::vector<DispatchRecord> log() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_log;
        }

        std::vector<wr::Batch> take()
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            auto held = std::move(m_held);
            m_held.clear();
            return held;
        }

        /// Takes every held batch and resolves each op with `result`; returns how many resolutions won.
        std::size_t resolveHeld(const ic::OpResult& result = ok())
        {
            auto batches = take();
            std::size_t won = 0;
            if (auto path = m_path.lock())
            {
                for (const auto& batch : batches)
                {
                    for (const auto& op : batch.ops)
                    {
                        won += path->resolve(batch.bucket, op, result) ? 1 : 0;
                    }
                }
            }
            return won;
        }

        bool stopped() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_stopped;
        }

        std::size_t afterStop() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_afterStop;
        }

        static ic::OpResult ok()
        {
            ic::OpResult result;
            result.status = ic::Status::Ok;
            return result;
        }

    private:
        std::weak_ptr<wr::WritePath> m_path;
        const Mode m_mode;
        mutable std::mutex m_mutex;
        std::condition_variable m_cv;
        std::size_t m_capacity;
        bool m_stopped {false};
        std::size_t m_afterStop {0};
        std::vector<DispatchRecord> m_log;
        std::vector<wr::Batch> m_held;
    };

    /// Callback results by a test-chosen key.
    class Results final : public std::enable_shared_from_this<Results>
    {
    public:
        static std::shared_ptr<Results> create()
        {
            return std::shared_ptr<Results>(new Results());
        }

        ic::Callback callback(std::uint64_t key)
        {
            return [self = shared_from_this(), key](const ic::OpResult& result)
            {
                {
                    std::lock_guard<std::mutex> lock(self->m_mutex);
                    ++self->m_count[key];
                    self->m_last[key] = result;
                    ++self->m_total;
                }
                self->m_cv.notify_all();
            };
        }

        bool waitTotal(std::size_t total, std::chrono::milliseconds timeout = 5s)
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            return m_cv.wait_for(lock, timeout, [&] { return m_total >= total; });
        }

        std::size_t total() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_total;
        }

        int count(std::uint64_t key) const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            const auto it = m_count.find(key);
            return it == m_count.end() ? 0 : it->second;
        }

        std::optional<ic::OpResult> result(std::uint64_t key) const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            const auto it = m_last.find(key);
            if (it == m_last.end())
            {
                return std::nullopt;
            }
            return it->second;
        }

        /// Keys whose (last) result has this status and cause.
        std::size_t countWith(ic::Status status, ic::Cause cause) const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            std::size_t n = 0;
            for (const auto& [key, result] : m_last)
            {
                n += (result.status == status && result.cause == cause) ? 1 : 0;
            }
            return n;
        }

        std::map<std::uint64_t, int> counts() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_count;
        }

    private:
        Results() = default;

        mutable std::mutex m_mutex;
        std::condition_variable m_cv;
        std::size_t m_total {0};
        std::map<std::uint64_t, int> m_count;
        std::map<std::uint64_t, ic::OpResult> m_last;
    };

    /// A JSON body of exactly `bytes` bytes (>= 8): {"p":"xxx..."}, built with an exact capacity (std::string(n, c)
    /// allocates n) so that the charge of an op carrying it has no heap slack: every exact charge of the
    /// suites stays wire + RESULT_RESERVE.
    inline std::string body(std::size_t bytes)
    {
        static constexpr char HEAD[] = R"({"p":")";
        static constexpr char TAIL[] = R"("})";
        const std::size_t fill = bytes > 8 ? bytes - 8 : 0;
        std::string out(fill + 8, 'x');
        out.replace(0, 6, HEAD, 6);
        out.replace(out.size() - 2, 2, TAIL, 2);
        return out;
    }

    inline ic::Op indexOp(std::string id, std::size_t bodyBytes = 16, std::string index = "wazuh-states-test")
    {
        ic::Op op;
        op.kind = ic::Op::Kind::Index;
        op.index = std::move(index);
        op.id = std::move(id);
        op.body = body(bodyBytes);
        return op;
    }

    /// The wire bytes of an encoded op or of an OpState (head + body + '\n').
    inline std::string wireOf(const wr::Encoded& encoded)
    {
        std::string out;
        wr::appendWire(out, encoded);
        return out;
    }
    inline std::string wireOf(const wr::OpState& op)
    {
        std::string out;
        wr::appendWire(out, op.headView(), op.body);
        return out;
    }

    /// The write path of the running case (set by WriteTest::start and BulkTest::startOn; the fixture's m_path keeps
    /// it alive after a stop()).
    inline std::weak_ptr<wr::WritePath>& casePath()
    {
        static std::weak_ptr<wr::WritePath> path;
        return path;
    }

    /// The bucket of an op a case holds without its batch: WritePath::resolve takes the bucket from its
    /// caller, the op keeps no reference to it. Looked up among the case path's live buckets by OpState::owner, which
    /// is never dereferenced (a dead owner is a test failure, not undefined behaviour).
    inline std::shared_ptr<wr::Bucket> bucketOf(const wr::OpState& op)
    {
        if (op.owner == nullptr)
        {
            return nullptr;
        }
        const auto path = casePath().lock();
        auto bucket = path ? path->liveBucket(op.owner) : nullptr;
        if (!bucket)
        {
            ADD_FAILURE() << "the op's bucket is not a live bucket of the case's write path";
        }
        return bucket;
    }

    /// Wire size of `op` (its NDJSON lines).
    inline std::uint64_t wireSize(ic::Op op)
    {
        auto encoded = wr::encode(std::move(op), ic::ConflictPolicy {});
        EXPECT_TRUE(encoded.ok()) << encoded.reason;
        return encoded.value.wire();
    }

    /// The charge of `op` without RESULT_RESERVE (wire + the heap slack of the body), on a copy of it. A copy's
    /// body has an exact capacity: a case that needs an op's own slack builds that op and reads the bucket's charge.
    inline std::uint64_t chargeOf(const ic::Op& op)
    {
        auto copy = op;
        auto encoded = wr::encode(std::move(copy), ic::ConflictPolicy {});
        EXPECT_TRUE(encoded.ok()) << encoded.reason;
        return encoded.value.charge();
    }

    /// A bucket spec with large thresholds (no batch unless the case lowers one) and no age-based batch for a minute.
    inline ic::BucketSpec bucketSpec(std::string name,
                                     std::size_t quotaBytes,
                                     ic::Overflow::Kind overflow = ic::Overflow::Kind::Reject,
                                     std::size_t maxBytes = 0,
                                     std::size_t maxDocs = 1000000,
                                     ic::Duration maxAge = ic::Duration {60000})
    {
        ic::BucketSpec spec;
        spec.name = std::move(name);
        spec.quotaBytes = quotaBytes;
        spec.overflow.kind = overflow;
        spec.overflow.blockTimeout = overflow == ic::Overflow::Kind::Block ? ic::Duration {5000} : ic::Duration {0};
        spec.bulk.maxBytes = maxBytes != 0 ? maxBytes : quotaBytes - wr::RESULT_RESERVE;
        spec.bulk.maxDocs = maxDocs;
        spec.bulk.maxAge = maxAge;
        return spec;
    }

    inline std::uint64_t rejectedTotal(const wr::BucketStats& s)
    {
        return s.rejectedQueueFull + s.rejectedClosed + s.submitTimeout + s.reentrancy + s.payloadTooLarge +
               s.invalidArgument + s.rejectedGroupTooLarge;
    }

    inline std::string describe(const wr::BucketStats& s)
    {
        std::ostringstream out;
        out << s.consumer << "/" << s.bucket << ": submitted " << s.submitted << " accepted " << s.accepted
            << " rejectedQueueFull " << s.rejectedQueueFull << " rejectedClosed " << s.rejectedClosed
            << " submitTimeout " << s.submitTimeout << " reentrancy " << s.reentrancy << " payloadTooLarge "
            << s.payloadTooLarge << " invalidArgument " << s.invalidArgument << " rejectedGroupTooLarge "
            << s.rejectedGroupTooLarge << " groupBuilding " << s.groupBuilding << " groupAbandoned " << s.groupAbandoned
            << " droppedNewest " << s.droppedNewest << " droppedOldest " << s.droppedOldest << " resolvedOk "
            << s.resolvedOk << " resolvedFailed " << s.resolvedFailed << " resolvedDropped " << s.resolvedDropped
            << " retained " << s.retained << " charge " << s.charge << " peakCharge " << s.peakCharge;
        return out.str();
    }

    inline std::string describe(const wr::WriteStats& stats)
    {
        std::ostringstream out;
        out << "global " << stats.globalCharge << "/" << stats.globalCap;
        for (const auto& bucket : stats.buckets)
        {
            out << "\n  " << describe(bucket);
        }
        return out.str();
    }

    /// The quota invariants of one bucket, with the groups' terms (bucket.hpp): a GroupTooLarge add is a
    /// refusal under `submitted`, and an op reserved by a group not committed yet is accepted but not retained.
    inline void expectInvariants(const wr::BucketStats& s)
    {
        EXPECT_EQ(s.submitted, s.accepted + rejectedTotal(s)) << describe(s);
        EXPECT_EQ(s.accepted, s.resolvedOk + s.resolvedFailed + s.resolvedDropped + s.retained + s.groupBuilding)
            << describe(s);
    }
} // namespace write_component

/// Every write component case: a runtime without the probe, the write path kept by the fixture, and in TearDown the
/// charge and the retained ops back at 0 (bounded wait), then shutdown and the hooks cleared.
class WriteTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        indexer_client::testing_hooks::resetAll();
        indexer_client::testing_hooks::setProbeAutoStart(false);
    }

    void TearDown() override
    {
        if (m_path)
        {
            const bool drained = component::eventually([this] { return drainedNow(); }, std::chrono::seconds(5));
            EXPECT_TRUE(drained) << "charge or retained ops left: " << write_component::describe(m_path->stats());
        }
        indexer_client::RuntimeOwner::shutdown();
        indexer_client::testing_hooks::resetAll();
        EXPECT_FALSE(indexer_client::RuntimeOwner::running());
        m_sink.reset();
        m_path.reset();
    }

    bool drainedNow() const
    {
        const auto stats = m_path->stats();
        if (stats.globalCharge != 0)
        {
            return false;
        }
        for (const auto& bucket : stats.buckets)
        {
            if (bucket.charge != 0 || bucket.retained != 0)
            {
                return false;
            }
        }
        return true;
    }

    /// Starts a runtime with K network and M CPU threads (plus any other `indexer_client_<name>` values).
    void start(std::uint32_t k = 1, std::uint32_t m = 2, std::map<std::string, std::string> extra = {})
    {
        std::map<std::string, std::string> values {{"analysisd.indexer_client_network_threads", std::to_string(k)},
                                                   {"analysisd.indexer_client_cpu_threads", std::to_string(m)}};
        for (auto& [name, value] : extra)
        {
            values["analysisd.indexer_client_" + name] = value;
        }
        auto started =
            indexer_client::RuntimeOwner::start(indexer_client::ProcessId::Analysisd, component::MapSource(values));
        ASSERT_TRUE(started.ok()) << indexer_client::toString(started.cause) << ": " << started.reason;
        m_ref = started.value;
        m_path = write_component::wr::runtimeWritePath();
        ASSERT_NE(m_path, nullptr);
        write_component::casePath() = m_path;
    }

    std::shared_ptr<write_component::TestSink>
    installSink(write_component::TestSink::Mode mode = write_component::TestSink::Mode::Hold,
                std::size_t capacity = write_component::TestSink::UNLIMITED)
    {
        m_sink = std::make_shared<write_component::TestSink>(m_path, mode, capacity);
        m_path->setSink(m_sink);
        return m_sink;
    }

    std::shared_ptr<indexer_client::Client> client(const std::string& consumer,
                                                   std::vector<indexer_client::BucketSpec> buckets)
    {
        auto created = m_ref.client(consumer, std::move(buckets));
        EXPECT_TRUE(created.ok()) << indexer_client::toString(created.cause) << ": " << created.reason;
        return created.value;
    }

    /// The counters of `consumer`/`bucket` (a default-constructed record if absent).
    write_component::wr::BucketStats stats(const std::string& bucket, const std::string& consumer = "c") const
    {
        for (auto& s : m_path->stats().buckets)
        {
            if (s.bucket == bucket && s.consumer == consumer)
            {
                return s;
            }
        }
        ADD_FAILURE() << "no bucket " << consumer << "/" << bucket;
        return {};
    }

    std::uint64_t globalCharge() const
    {
        return m_path->stats().globalCharge;
    }

    /// requestClose() only closes the admission and the buckets keep draining; through a TestSink that
    /// holds, or has no capacity, nothing drains. A case that needs the close to resolve what is queued closes with a
    /// short deadline instead: at drainEnd (now + 600 ms for 1 s) the queued ops are Dropped(ClientClosed) and those
    /// the sink holds Dropped(Shutdown).
    void closeNow(indexer_client::Client& c, std::chrono::milliseconds deadline = std::chrono::milliseconds(1000))
    {
        const auto report = c.awaitClosed(std::chrono::steady_clock::now() + deadline);
        EXPECT_TRUE(report.ok()) << indexer_client::toString(report.cause);
    }

    indexer_client::RuntimeRef m_ref;
    std::shared_ptr<write_component::wr::WritePath> m_path;
    std::shared_ptr<write_component::TestSink> m_sink;
};

/// The write cases that break an internal invariant on purpose. Every ERROR line of the library is kept
/// (the log function is installed before the case starts its runtime), and the case reads
/// testing_hooks::internalErrors() around the broken invariant: logged and counted, never an abort.
class WriteInternalErrorTest : public WriteTest
{
protected:
    /// loggerHelper.h's LOGLEVEL_ERROR, as the library passes it to the log function.
    static constexpr int ERROR_LEVEL = 3;

    void SetUp() override
    {
        WriteTest::SetUp();
        auto lines = m_errors;
        indexer_client::setLogFunction(
            [lines](const int level, const char*, const char*, const int, const char*, const char* format, va_list args)
            {
                if (level != ERROR_LEVEL)
                {
                    return;
                }
                va_list copy;
                va_copy(copy, args);
                char buffer[1024];
                std::vsnprintf(buffer, sizeof(buffer), format, copy);
                va_end(copy);
                std::lock_guard<std::mutex> lock(lines->mutex);
                lines->text.emplace_back(buffer);
            });
    }

    void TearDown() override
    {
        WriteTest::TearDown();
        indexer_client::setLogFunction({}); // The runtime is down: valid again.
    }

    /// ERROR lines containing `part`.
    std::size_t errors(const std::string& part) const
    {
        std::lock_guard<std::mutex> lock(m_errors->mutex);
        std::size_t n = 0;
        for (const auto& line : m_errors->text)
        {
            n += line.find(part) != std::string::npos ? 1 : 0;
        }
        return n;
    }

private:
    struct Lines final
    {
        std::mutex mutex;
        std::vector<std::string> text;
    };
    std::shared_ptr<Lines> m_errors = std::make_shared<Lines>();
};

#endif // _INDEXER_CLIENT_TESTS_COMPONENT_WRITE_FIXTURE_HPP
