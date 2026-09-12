#ifndef CMCONTENT_CONTENT_TOPIC_HPP
#define CMCONTENT_CONTENT_TOPIC_HPP

#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>

#include <json.hpp>

#include <contentSink.hpp>
#include <contentTokenStore.hpp>
#include <contentTypes.hpp>

namespace cmcontent
{

/**
 * @brief One registered content topic, as its owner needs to see it.
 *
 * `ContentRegister` is a concrete class that registers itself with a process-wide facade and opens
 * real connections to the indexer on construction, so a sync service holding one directly cannot be
 * tested without an indexer. That is not a hypothetical: it is why the orchestration in `CMSync` and
 * `IocSync` — which outcome makes a space FAILED, when a missing database forces a full reload, what
 * happens when a cycle is already running — had no unit coverage at all. This interface is the seam
 * that gives it some.
 */
class IContentTopic
{
public:
    virtual ~IContentTopic() = default;

    /**
     * @brief Run exactly one content cycle, synchronously.
     *
     * @param request What the caller wants from this cycle.
     * @return What the cycle did. Never throws.
     */
    virtual content_manager::CycleOutcome runOnce(content_manager::RunRequest request = {}) noexcept = 0;

    /**
     * @brief Ask an in-flight cycle to wind down at its next checkpoint.
     */
    virtual void requestStop() noexcept = 0;
};

/**
 * @brief Builds the topic object for a registration.
 *
 * Defaults to @ref defaultTopicFactory; tests substitute one that returns a fake.
 */
using TopicFactory = std::function<std::unique_ptr<IContentTopic>(
    const std::string& topicName,
    const nlohmann::json& parameters,
    std::shared_ptr<content_manager::IContentSink> sink,
    std::shared_ptr<content_manager::IContentTokenStore> tokenStore)>;

/**
 * @brief The production factory: builds a real `ContentRegister`.
 *
 * @return A factory registering topics with the shared content manager.
 */
TopicFactory defaultTopicFactory();

/**
 * @brief One topic's change-detection token, safe to touch from any thread.
 *
 * The token is read and written by the content cycle, which runs on whichever thread drove it — the
 * sync service's scheduler task for a scheduled run, an on-demand lane worker for an API-triggered
 * one. Those are different threads, and the second is not serialised against the first by anything
 * the sync service holds. Routing the token through this cell instead of through the service's own
 * state vector is what keeps that safe: the vector stays single-threaded and is reconciled from the
 * cells at cycle boundaries, where the owning thread already holds its own lock.
 */
class TokenCell final
{
public:
    /**
     * @brief Build a cell.
     *
     * @param initial Token to start from; "" when nothing has been committed.
     */
    explicit TokenCell(std::string initial = {})
        : m_value(std::move(initial))
    {
    }

    /// @return The current token.
    std::string get() const
    {
        std::lock_guard<std::mutex> lock {m_mutex};
        return m_value;
    }

    /**
     * @brief Replace the token.
     *
     * @param value New token.
     */
    void set(std::string value)
    {
        std::lock_guard<std::mutex> lock {m_mutex};
        m_value = std::move(value);
    }

private:
    mutable std::mutex m_mutex;
    std::string m_value;
};

/**
 * @brief A token store backed by a @ref TokenCell.
 *
 * @param cell The cell to read and write. Must outlive the registration.
 * @return The token store to hand to the registration.
 */
std::shared_ptr<content_manager::IContentTokenStore> cellTokenStore(std::shared_ptr<TokenCell> cell);

/**
 * @brief A read-only token store backed by a caller-supplied loader.
 *
 * For topics whose token is not stored but *derived* — `cmsync` reads the hash of the ruleset the
 * router currently serves, so the deployed state is the token and there is nothing separate to keep
 * in step with it.
 *
 * @param loader Reads the current token. Must be safe to call from any thread.
 * @return The token store to hand to the registration.
 */
std::shared_ptr<content_manager::IContentTokenStore> derivedTokenStore(std::function<std::string()> loader);

} // namespace cmcontent

#endif // CMCONTENT_CONTENT_TOPIC_HPP
