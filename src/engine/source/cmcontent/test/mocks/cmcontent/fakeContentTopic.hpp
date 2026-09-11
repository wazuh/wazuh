#ifndef CMCONTENT_FAKE_CONTENT_TOPIC_HPP
#define CMCONTENT_FAKE_CONTENT_TOPIC_HPP

#include <algorithm>
#include <exception>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include <cmcontent/contentTopic.hpp>

namespace cmcontent::mocks
{

/**
 * @brief A scripted @ref IContentTopic, plus the registry a test drives it through.
 *
 * The sync services own concrete `ContentRegister`s in production, which register themselves with a
 * process-wide facade and open real connections on construction — so the orchestration around them
 * (which outcome makes a type FAILED, when a missing database forces a full reload, what a
 * already-running cycle does to the persisted state) could not be exercised at all. Injecting a
 * factory that hands out these instead is what makes that testable.
 *
 * The fake deliberately does the two things a real topic does that the orchestration depends on:
 * it can report any `CycleOutcome`, and it can write to the token store it was given, which is how
 * a committed hash reaches the service's state.
 */
class FakeTopicRegistry
{
public:
    /// What one `runOnce` on a topic should do.
    struct Script
    {
        content_manager::CycleOutcome outcome;  ///< What to report.
        std::string tokenToStore;               ///< Written to the token store first; "" writes nothing.
        bool clearToken {false};                ///< Clear the token store instead of writing.

        /// Optional: exercise the sink the way a real cycle would, so the caller's handling of what
        /// the sink leaves behind is covered too. A `CycleOutcome` alone cannot express that — for
        /// `cmsync` the interesting result of a cycle is the sink's `RulesetOutcome`, not the
        /// status.
        std::function<void(content_manager::IContentSink&)> driveSink;
    };

    /// One recorded call.
    struct Call
    {
        std::string topic;
        content_manager::RunRequest request;
    };

    /**
     * @brief The factory to hand to the service under test.
     *
     * @return A factory producing topics bound to this registry.
     */
    TopicFactory factory()
    {
        return [this](const std::string& topicName,
                      const nlohmann::json& parameters,
                      std::shared_ptr<content_manager::IContentSink> sink,
                      std::shared_ptr<content_manager::IContentTokenStore> tokenStore)
                   -> std::unique_ptr<IContentTopic>
        {
            {
                std::lock_guard<std::mutex> lock {m_mutex};
                m_registered.push_back(topicName);
                m_parameters[topicName] = parameters;
                m_sinks[topicName] = sink;
                m_tokenStores[topicName] = tokenStore;
            }
            return std::make_unique<Topic>(*this, topicName);
        };
    }

    /**
     * @brief Script the outcomes a topic returns, one per call, last one repeating.
     *
     * @param topic Topic name.
     * @param scripts Outcomes to return in order.
     */
    void script(const std::string& topic, std::vector<Script> scripts)
    {
        std::lock_guard<std::mutex> lock {m_mutex};
        m_scripts[topic] = std::move(scripts);
    }

    /// @param topic Topic name.
    /// @param status Single outcome status to report on every call.
    void scriptStatus(const std::string& topic, content_manager::CycleStatus status)
    {
        Script single;
        single.outcome.status = status;
        script(topic, {single});
    }

    /// @return Every topic name registered, in registration order.
    std::vector<std::string> registered() const
    {
        std::lock_guard<std::mutex> lock {m_mutex};
        return m_registered;
    }

    /// @return Every runOnce call, in order.
    std::vector<Call> calls() const
    {
        std::lock_guard<std::mutex> lock {m_mutex};
        return m_calls;
    }

    /// @return How many times @p topic was run.
    std::size_t callCount(const std::string& topic) const
    {
        std::lock_guard<std::mutex> lock {m_mutex};
        return static_cast<std::size_t>(
            std::count_if(m_calls.begin(), m_calls.end(), [&topic](const Call& call) { return call.topic == topic; }));
    }

    /// @return How many times @p topic was asked to stop.
    std::size_t stopCount(const std::string& topic) const
    {
        std::lock_guard<std::mutex> lock {m_mutex};
        const auto it = m_stops.find(topic);
        return it == m_stops.end() ? 0U : it->second;
    }

    /// @return The registration parameters a topic was built with.
    nlohmann::json parametersOf(const std::string& topic) const
    {
        std::lock_guard<std::mutex> lock {m_mutex};
        const auto it = m_parameters.find(topic);
        return it == m_parameters.end() ? nlohmann::json {} : it->second;
    }

    /// @return The sink a topic was built with.
    std::shared_ptr<content_manager::IContentSink> sinkOf(const std::string& topic) const
    {
        std::lock_guard<std::mutex> lock {m_mutex};
        const auto it = m_sinks.find(topic);
        return it == m_sinks.end() ? nullptr : it->second;
    }

    /// @return The token store a topic was built with.
    std::shared_ptr<content_manager::IContentTokenStore> tokenStoreOf(const std::string& topic) const
    {
        std::lock_guard<std::mutex> lock {m_mutex};
        const auto it = m_tokenStores.find(topic);
        return it == m_tokenStores.end() ? nullptr : it->second;
    }

private:
    class Topic final : public IContentTopic
    {
    public:
        Topic(FakeTopicRegistry& registry, std::string topic)
            : m_registry(registry)
            , m_topic(std::move(topic))
        {
        }

        content_manager::CycleOutcome runOnce(content_manager::RunRequest request) noexcept override
        {
            // The real topic is noexcept all the way down, so this has to be too. Without the
            // catch, anything a scripted `driveSink` throws becomes a terminate, and a CI log that
            // says only "terminate called" is a miserable thing to debug.
            try
            {
                return m_registry.run(m_topic, request);
            }
            catch (const std::exception& e)
            {
                content_manager::CycleOutcome outcome;
                outcome.status = content_manager::CycleStatus::FailedSink;
                outcome.detail = std::string {"the scripted topic threw: "} + e.what();
                return outcome;
            }
            catch (...)
            {
                content_manager::CycleOutcome outcome;
                outcome.status = content_manager::CycleStatus::FailedSink;
                outcome.detail = "the scripted topic threw";
                return outcome;
            }
        }

        void requestStop() noexcept override { m_registry.stop(m_topic); }

    private:
        FakeTopicRegistry& m_registry;
        std::string m_topic;
    };

    content_manager::CycleOutcome run(const std::string& topic, content_manager::RunRequest request)
    {
        Script script;
        std::shared_ptr<content_manager::IContentTokenStore> tokenStore;
        std::shared_ptr<content_manager::IContentSink> sink;
        {
            std::lock_guard<std::mutex> lock {m_mutex};
            m_calls.push_back(Call {topic, request});

            if (const auto it = m_scripts.find(topic); it != m_scripts.end() && !it->second.empty())
            {
                const auto index = std::min(m_scriptIndex[topic]++, it->second.size() - 1);
                script = it->second[index];
            }

            if (const auto it = m_tokenStores.find(topic); it != m_tokenStores.end())
            {
                tokenStore = it->second;
            }
            if (const auto it = m_sinks.find(topic); it != m_sinks.end())
            {
                sink = it->second;
            }
        }

        // Outside the lock: both of these reach back into the service under test, and holding a lock
        // across that would model something the real topic does not do.
        if (script.driveSink && sink)
        {
            script.driveSink(*sink);
        }

        if (tokenStore)
        {
            if (script.clearToken)
            {
                tokenStore->clear(topic);
            }
            else if (!script.tokenToStore.empty())
            {
                tokenStore->store(topic, script.tokenToStore);
            }
        }

        return script.outcome;
    }

    void stop(const std::string& topic)
    {
        std::lock_guard<std::mutex> lock {m_mutex};
        ++m_stops[topic];
    }

    mutable std::mutex m_mutex;
    std::vector<std::string> m_registered;
    std::vector<Call> m_calls;
    std::unordered_map<std::string, nlohmann::json> m_parameters;
    std::unordered_map<std::string, std::shared_ptr<content_manager::IContentSink>> m_sinks;
    std::unordered_map<std::string, std::shared_ptr<content_manager::IContentTokenStore>> m_tokenStores;
    std::unordered_map<std::string, std::vector<Script>> m_scripts;
    std::unordered_map<std::string, std::size_t> m_scriptIndex;
    std::unordered_map<std::string, std::size_t> m_stops;
};

} // namespace cmcontent::mocks

#endif // CMCONTENT_FAKE_CONTENT_TOPIC_HPP
