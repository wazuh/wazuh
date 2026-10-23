// SPDX-License-Identifier: AGPL-3.0-or-later
#include <stdexcept>
#include <utility>

#include <base/utils/metaHelpers.hpp>
#include <contentRegister.hpp>

#include <cmcontent/contentTopic.hpp>

namespace cmcontent
{

namespace
{

/// The production @ref IContentTopic: a thin owner of one `ContentRegister`.
class ContentRegisterTopic final : public IContentTopic
{
public:
    ContentRegisterTopic(const std::string& topicName,
                         const content_manager::TopicSpec& spec,
                         std::shared_ptr<content_manager::IContentSink> sink,
                         std::shared_ptr<content_manager::IContentIndexer> indexer,
                         std::shared_ptr<content_manager::IContentTokenStore> tokenStore)
        : m_register(topicName, spec, std::move(sink), std::move(indexer), std::move(tokenStore))
    {
    }

    content_manager::CycleOutcome runOnce(content_manager::RunRequest request) noexcept override
    {
        return m_register.runOnce(request);
    }

    void requestStop() noexcept override { m_register.requestStop(); }

private:
    ContentRegister m_register;
};

bool isRetryable(content_manager::CycleStatus status)
{
    return status == content_manager::CycleStatus::FailedTransport
           || status == content_manager::CycleStatus::FailedSink;
}

} // namespace

TopicFactory defaultTopicFactory(std::shared_ptr<content_manager::IContentIndexer> indexer)
{
    if (!indexer)
    {
        throw std::invalid_argument {"The content registrations need the Engine's indexer; got null"};
    }

    return [indexer = std::move(indexer)](
               const std::string& topicName,
               const content_manager::TopicSpec& spec,
               std::shared_ptr<content_manager::IContentSink> sink,
               std::shared_ptr<content_manager::IContentTokenStore> tokenStore) -> std::unique_ptr<IContentTopic>
    {
        return std::make_unique<ContentRegisterTopic>(topicName, spec, std::move(sink), indexer, std::move(tokenStore));
    };
}

content_manager::CycleOutcome runWithRetries(IContentTopic& topic,
                                             const content_manager::RunRequest& request,
                                             const RetryPolicy& retry,
                                             const std::atomic<bool>& stop,
                                             const std::string& component,
                                             std::string_view what)
{
    content_manager::CycleOutcome last;
    last.status = content_manager::CycleStatus::SkippedStopRequested;
    last.detail = "stop requested before the cycle started";

    try
    {
        // executeWithRetry retries on an exception; a retryable outcome is rethrown to drive it.
        return base::utils::executeWithRetry(
            [&]()
            {
                last = topic.runOnce(request);
                if (isRetryable(last.status))
                {
                    throw std::runtime_error(last.detail);
                }
                return last;
            },
            component,
            what,
            retry.maxAttempts,
            retry.waitSeconds,
            stop);
    }
    catch (const std::exception&)
    {
        return last;
    }
}

} // namespace cmcontent
