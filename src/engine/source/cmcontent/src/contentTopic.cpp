// SPDX-License-Identifier: AGPL-3.0-or-later
#include <stdexcept>
#include <utility>

#include <base/logging.hpp>
#include <contentOnDemand.hpp>
#include <contentRegister.hpp>

#include <cmcontent/contentTopic.hpp>
#include <cmcontent/engineTokenStore.hpp>

namespace cmcontent
{

namespace
{

/// The production @ref IContentTopic: a thin owner of one `ContentRegister`.
class ContentRegisterTopic final : public IContentTopic
{
public:
    ContentRegisterTopic(const std::string& topicName,
                         const nlohmann::json& parameters,
                         std::shared_ptr<content_manager::IContentSink> sink,
                         std::shared_ptr<content_manager::IContentIndexer> indexer,
                         std::shared_ptr<content_manager::IContentTokenStore> tokenStore)
        : m_register(std::make_unique<ContentRegister>(
              topicName, parameters, std::move(sink), std::move(indexer), std::move(tokenStore)))
    {
    }

    content_manager::CycleOutcome runOnce(content_manager::RunRequest request) noexcept override
    {
        return m_register->runOnce(request);
    }

    void requestStop() noexcept override { m_register->requestStop(); }

private:
    std::unique_ptr<ContentRegister> m_register;
};

} // namespace

TopicFactory defaultTopicFactory(std::shared_ptr<content_manager::IContentIndexer> indexer)
{
    if (!indexer)
    {
        throw std::invalid_argument {"The content registrations need the Engine's indexer; got null"};
    }

    return [indexer = std::move(indexer)](
               const std::string& topicName,
               const nlohmann::json& parameters,
               std::shared_ptr<content_manager::IContentSink> sink,
               std::shared_ptr<content_manager::IContentTokenStore> tokenStore) -> std::unique_ptr<IContentTopic>
    {
        return std::make_unique<ContentRegisterTopic>(
            topicName, parameters, std::move(sink), indexer, std::move(tokenStore));
    };
}

namespace
{

/// One on-demand sequence, shared by the completions that walk it.
struct OnDemandSequence
{
    std::vector<std::string> topics;
    std::string component;
    OnDemandDispatch dispatch;
};

void dispatchFrom(const std::shared_ptr<const OnDemandSequence>& sequence, std::size_t index)
{
    if (index >= sequence->topics.size())
    {
        return;
    }

    // The completion of this topic queues the next one. It runs on a lane worker with no lane lock
    // held (or inline, for a rejection), so queuing from inside it is safe; the recursion is bounded
    // by the number of topics.
    sequence->dispatch(
        sequence->topics[index],
        content_manager::RunRequest {false, true},
        [sequence, index](content_manager::OnDemandResult result)
        {
            const auto& topic = sequence->topics[index];
            switch (result.code)
            {
                case content_manager::OnDemandCode::Completed:
                    LOG_DEBUG("[{}] On-demand update of '{}' finished", sequence->component, topic);
                    break;

                case content_manager::OnDemandCode::QueueFull:
                case content_manager::OnDemandCode::ShuttingDown:
                {
                    // Whatever made this one fail will fail the rest too; say exactly what was skipped.
                    std::string skipped;
                    for (auto next = index + 1; next < sequence->topics.size(); ++next)
                    {
                        skipped += (skipped.empty() ? "'" : ", '") + sequence->topics[next] + "'";
                    }
                    LOG_WARNING("[{}] On-demand update of '{}' was not run: {}. Not requested either: {}",
                                sequence->component,
                                topic,
                                result.detail,
                                skipped.empty() ? std::string {"none"} : skipped);
                    return;
                }

                default:
                    LOG_WARNING(
                        "[{}] On-demand update of '{}' was not run: {}", sequence->component, topic, result.detail);
                    break;
            }

            dispatchFrom(sequence, index + 1);
        });
}

} // namespace

void requestOnDemandInSequence(std::vector<std::string> topics, std::string component, OnDemandDispatch dispatch)
{
    if (!dispatch)
    {
        dispatch = [](const std::string& topic,
                      content_manager::RunRequest request,
                      std::function<void(content_manager::OnDemandResult)> completion)
        {
            content_manager::requestOnDemand(topic, request, std::move(completion));
        };
    }

    dispatchFrom(std::make_shared<const OnDemandSequence>(
                     OnDemandSequence {std::move(topics), std::move(component), std::move(dispatch)}),
                 0);
}

std::shared_ptr<content_manager::IContentTokenStore> cellTokenStore(std::shared_ptr<TokenCell> cell)
{
    return std::make_shared<EngineTokenStore>([cell](std::string_view) { return cell->get(); },
                                              [cell](std::string_view, std::string_view token)
                                              {
                                                  cell->set(std::string {token});
                                                  return true;
                                              });
}

std::shared_ptr<content_manager::IContentTokenStore> derivedTokenStore(std::function<std::string()> loader)
{
    return std::make_shared<EngineTokenStore>(
        [loader = std::move(loader)](std::string_view) { return loader(); },
        // Nothing to write: the token is a property of state the commit already changed, so storing
        // it separately could only create a second answer that disagrees with the first.
        [](std::string_view, std::string_view) { return true; });
}

} // namespace cmcontent
