/*
 * Wazuh container_instances — DockerConnector reconcile-debounce tests
 * (#37532 / #37203 O9, "C16").
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * These exist because the debounce used to LOSE work rather than defer it.
 *
 * handleEvent() re-seeds only when the debounce window has elapsed, and a
 * re-seed is a full snapshot taken at an instant. A container that starts
 * inside the window is therefore in neither the previous snapshot nor any
 * later one, because nothing re-ran the snapshot: the pending flag was set and
 * never read. On a host that goes quiet right after a burst — a deploy, a
 * compose up — the last container started simply never entered the store.
 *
 * That is not a staleness bug. Consumers read the store, so no consumer-side
 * poll and no change notification can surface a container the store never
 * recorded; and because the grace-expiry sweep also lives inside
 * applySnapshot(), the same gap strands removed records indefinitely.
 *
 * The fix gives the debounce a trailing edge, driven by the event stream's idle
 * tick. Both tests below fail without it.
 */

#include "docker/docker_connector.hpp"

#include "cache/metadata_store.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <string>
#include <thread>
#include <vector>

using namespace wazuh::container_instances;

namespace
{

    constexpr auto DEBOUNCE = std::chrono::milliseconds {500};

    /// Comfortably past the debounce window without being slow enough to annoy.
    constexpr auto PAST_DEBOUNCE = std::chrono::milliseconds {650};

    std::uint64_t InodeFor(const std::string& containerId)
    {
        // Any stable non-zero mapping; listContainers() hides hostKey == 0.
        return 1000 + containerId.size() + static_cast<std::uint64_t>(containerId.back());
    }

    /// Resolver that claims every container the test has "started" is joined to a
    /// cgroup, which is what makes it visible through listContainers().
    class FakeResolver final : public ICgroupResolver
    {
    public:
        void setRunning(std::vector<std::string> ids)
        {
            m_running = std::move(ids);
        }

        [[nodiscard]] CgroupScan scan() const override
        {
            CgroupScan out;
            for (const auto& id : m_running)
            {
                CgroupEntry entry;
                entry.containerId = id;
                entry.inode = InodeFor(id);
                entry.hint = RuntimeHint::docker;
                out.containers.push_back(entry);
                out.allHostKeys.insert(entry.inode);
            }
            return out;
        }

        [[nodiscard]] std::optional<CgroupEntry> scanOne(std::uint64_t) const override
        {
            return std::nullopt;
        }

    private:
        std::vector<std::string> m_running;
    };

    /// Drives the connector through a scripted event stream. `streamEvents` is the
    /// whole test: it delivers a burst, then goes silent and only ticks `onIdle`,
    /// which is exactly the shape a quiet host produces.
    class ScriptedDockerApi final : public IDockerApiClient
    {
    public:
        explicit ScriptedDockerApi(FakeResolver& resolver)
            : m_resolver(resolver)
        {
        }

        /// The containers the daemon would report right now.
        void setContainers(std::vector<std::string> ids)
        {
            m_resolver.setRunning(ids);
            m_containers = std::move(ids);
        }

        [[nodiscard]] std::string negotiateVersion() override
        {
            return "1.41";
        }

        [[nodiscard]] std::vector<ContainerSummary> listContainers() override
        {
            ++listCalls;
            std::vector<ContainerSummary> out;
            out.reserve(m_containers.size());
            for (const auto& id : m_containers)
            {
                out.push_back(ContainerSummary {id});
            }
            return out;
        }

        [[nodiscard]] ContainerDetail inspect(const std::string& containerId) override
        {
            ContainerDetail detail;
            detail.record.runtime = ContainerRuntime::docker;
            detail.record.containerId = containerId;
            detail.record.containerName = containerId;
            detail.record.image = "img";
            return detail;
        }

        [[nodiscard]] StreamOutcome streamEvents(std::int64_t,
                                                 const DockerEventSink& sink,
                                                 const StopController& stop,
                                                 const std::function<void()>& onIdle) override
        {
            script(sink, onIdle, stop);

            StreamOutcome outcome;
            outcome.kind = StreamOutcome::Kind::cancelled; // run() returns, test ends.
            return outcome;
        }

        /// Set by the test; receives the live sink and idle hook.
        std::function<void(const DockerEventSink&, const std::function<void()>&, const StopController&)> script;

        std::atomic<int> listCalls {0};

    private:
        FakeResolver& m_resolver;
        std::vector<std::string> m_containers;
    };

    struct Fixture
    {
        FakeResolver resolver;
        ScriptedDockerApi api {resolver};
        MetadataStore store {[](LogLevel, const std::string&) {}};
        StopController stop;

        DockerConnector connector {api, resolver, store, SourceId {"docker"}, [](LogLevel, const std::string&) {}};

        [[nodiscard]] std::vector<std::string> listed()
        {
            std::vector<std::string> out;
            for (const auto& record : store.listContainers())
            {
                out.push_back(record->containerId);
            }
            std::sort(out.begin(), out.end());
            return out;
        }
    };

    bool Contains(const std::vector<std::string>& haystack, const std::string& needle)
    {
        return std::find(haystack.begin(), haystack.end(), needle) != haystack.end();
    }

} // namespace

TEST(DockerConnectorDebounceTest, LastEventOfABurstIsNotDropped)
{
    Fixture f;

    f.api.script = [&f](const DockerEventSink& sink, const std::function<void()>& onIdle, const StopController&)
    {
        // "alpha" starts: the debounce has never fired, so this re-seeds now.
        f.api.setContainers({"alpha"});
        sink(DockerEvent {"alpha", "start", 1});

        // "beta" starts a moment later — inside the debounce window, so its
        // event is coalesced away. Crucially the snapshot taken for "alpha"
        // predates beta, so nothing has ever observed beta.
        f.api.setContainers({"alpha", "beta"});
        sink(DockerEvent {"beta", "start", 2});

        // ...and now the host goes quiet. No further events, ever. Only the
        // stream's idle tick keeps arriving.
        std::this_thread::sleep_for(PAST_DEBOUNCE);
        onIdle();
    };

    f.connector.run(f.stop);

    const auto listed = f.listed();
    EXPECT_TRUE(Contains(listed, "alpha"));
    EXPECT_TRUE(Contains(listed, "beta")) << "beta started inside the debounce window and the host then went "
                                             "quiet; without a trailing-edge flush it is never recorded at all, "
                                             "and no consumer-side poll can recover it";
}

TEST(DockerConnectorDebounceTest, QuietStreamStillReconcilesWithinDeadline)
{
    Fixture f;

    f.api.script = [&f](const DockerEventSink& sink, const std::function<void()>& onIdle, const StopController&)
    {
        f.api.setContainers({"alpha"});
        sink(DockerEvent {"alpha", "start", 1});

        f.api.setContainers({"alpha", "beta"});
        sink(DockerEvent {"beta", "start", 2}); // suppressed

        // The idle tick fires on its own interval regardless of traffic. Before
        // the window elapses it must do nothing (no wasted full re-seed), and
        // after it must flush exactly once.
        const auto listsBefore = f.api.listCalls.load();
        onIdle();
        EXPECT_EQ(listsBefore, f.api.listCalls.load()) << "an idle tick inside the debounce window must not re-seed";

        std::this_thread::sleep_for(PAST_DEBOUNCE);

        onIdle();
        const auto listsAfterFlush = f.api.listCalls.load();
        EXPECT_GT(listsAfterFlush, listsBefore) << "the first idle tick past the window must flush the deferral";

        // Pending is now clear, so further ticks on a still-quiet stream are free.
        onIdle();
        onIdle();
        EXPECT_EQ(listsAfterFlush, f.api.listCalls.load())
            << "idle ticks with nothing pending must not re-seed; otherwise a quiet host pays a full "
               "list+inspect sweep every poll interval";
    };

    f.connector.run(f.stop);

    EXPECT_TRUE(Contains(f.listed(), "beta"));
}
