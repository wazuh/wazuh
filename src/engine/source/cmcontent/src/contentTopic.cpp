#include <utility>

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
                         std::shared_ptr<content_manager::IContentTokenStore> tokenStore)
        : m_register(std::make_unique<ContentRegister>(topicName, parameters, std::move(sink), std::move(tokenStore)))
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

TopicFactory defaultTopicFactory()
{
    return [](const std::string& topicName,
              const nlohmann::json& parameters,
              std::shared_ptr<content_manager::IContentSink> sink,
              std::shared_ptr<content_manager::IContentTokenStore> tokenStore) -> std::unique_ptr<IContentTopic>
    {
        return std::make_unique<ContentRegisterTopic>(topicName, parameters, std::move(sink), std::move(tokenStore));
    };
}

std::shared_ptr<content_manager::IContentTokenStore> cellTokenStore(std::shared_ptr<TokenCell> cell)
{
    return std::make_shared<EngineTokenStore>(
        [cell](std::string_view) { return cell->get(); },
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
