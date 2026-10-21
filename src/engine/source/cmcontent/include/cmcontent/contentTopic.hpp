// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef CMCONTENT_CONTENT_TOPIC_HPP
#define CMCONTENT_CONTENT_TOPIC_HPP

#include <atomic>
#include <cstddef>
#include <functional>
#include <memory>
#include <string>
#include <string_view>

#include <contentIndexer.hpp>
#include <contentSink.hpp>
#include <contentTokenStore.hpp>
#include <contentTopicSpec.hpp>
#include <contentTypes.hpp>

namespace cmcontent
{

/**
 * @brief One registered content topic, as a sync service drives it.
 *
 * The seam between the sync services and `ContentRegister`, so their orchestration can be tested
 * with a scripted topic instead of an indexer.
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
     * @brief Stop the topic for good: the in-flight cycle winds down, later ones are skipped.
     */
    virtual void requestStop() noexcept = 0;
};

/**
 * @brief Builds the topic object for a registration.
 */
using TopicFactory =
    std::function<std::unique_ptr<IContentTopic>(const std::string& topicName,
                                                 const content_manager::TopicSpec& spec,
                                                 std::shared_ptr<content_manager::IContentSink> sink,
                                                 std::shared_ptr<content_manager::IContentTokenStore> tokenStore)>;

/**
 * @brief The production factory: a `ContentRegister` over the Engine's indexer.
 *
 * @param indexer The Engine's indexer, shared by every topic (D1 of the content manager).
 * @return The factory.
 * @throws std::invalid_argument if @p indexer is null.
 */
TopicFactory defaultTopicFactory(std::shared_ptr<content_manager::IContentIndexer> indexer);

/// How often a failed cycle is retried before the sync service reports it.
struct RetryPolicy
{
    std::size_t maxAttempts {3}; ///< Cycles per run, the first included. At least one runs.
    std::size_t waitSeconds {5}; ///< Pause between attempts.
};

/**
 * @brief Run a topic, retrying a transport or sink failure.
 *
 * A deferral, a configuration failure or a stop is returned at once: retrying cannot change it
 * within one run.
 *
 * @param topic The topic.
 * @param request What each cycle should do.
 * @param retry How often to retry.
 * @param stop Ends the retries early.
 * @param component The caller, as its log lines name it.
 * @param what Names the run in the retry log lines.
 * @return The last cycle's outcome; `SkippedStopRequested` when @p stop ended it before a cycle ran.
 */
content_manager::CycleOutcome runWithRetries(IContentTopic& topic,
                                             const content_manager::RunRequest& request,
                                             const RetryPolicy& retry,
                                             const std::atomic<bool>& stop,
                                             const std::string& component,
                                             std::string_view what);

} // namespace cmcontent

#endif // CMCONTENT_CONTENT_TOPIC_HPP
