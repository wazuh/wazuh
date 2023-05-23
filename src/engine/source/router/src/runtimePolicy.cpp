#include <router/runtimePolicy.hpp>

#include <base/parseEvent.hpp>
#include <logging/logging.hpp>
#include <rxbk/rxFactory.hpp>
#include <utils/getExceptionStack.hpp>
#include <re2/re2.h>

namespace router
{

std::optional<base::Error> RuntimePolicy::build(std::shared_ptr<builder::Builder> builder)
{
    if (m_spController)
    {
        return base::Error {fmt::format("Policy '{}' is already built", m_asset)};
    }

    try
    {
        // Build the policy and create the pipeline
        m_environment = builder->buildPolicy(m_asset);
        m_spController = std::make_shared<rxbk::Controller>(rxbk::buildRxPipeline(m_environment));
    }
    catch (std::exception& e)
    {
        return base::Error {fmt::format("Error building policy [{}]: {}", m_asset, utils::getExceptionStack(e))};
    }

    return std::nullopt;
}

std::optional<base::Error> RuntimePolicy::processEvent(base::Event event)
{
    if (!m_spController)
    {
        return base::Error {fmt::format("Policy '{}' is not built", m_asset)};
    }
    auto result = base::result::makeSuccess(event);
    m_spController->ingestEvent(std::make_shared<base::result::Result<base::Event>>(std::move(result)));

    subscribeToOutput();

    return std::nullopt;
}

void RuntimePolicy::subscribeToOutput()
{
    auto subscriber = rxcpp::make_subscriber<rxbk::RxEvent>(
        [&](const rxbk::RxEvent& event) {
            std::stringstream output;
            output << event->payload()->prettyStr() << std::endl;
            m_output = output.str();
        });

    m_spController->getOutput().subscribe(subscriber);
}

void RuntimePolicy::listenAllTrace()
{
    if (0)
    {
        auto conditionRegex = std::make_shared<RE2>(R"(\[([^\]]+)\] \[condition\]:(.+))");
        m_spController->listenOnAllTrace(rxcpp::make_subscriber<std::string>(
            [&](const std::string& trace)
            {
                std::string asset;
                std::string result;
                auto matched = RE2::FullMatch(trace, *conditionRegex, &asset, &result);
                if (matched)
                {
                    m_history.push_back({asset, result});
                }
            }));
    }
    if (1)
    {
        auto assetNamePattern = std::make_shared<RE2>(R"(^\[([^\]]+)\].+)");
        m_spController->listenOnAllTrace(rxcpp::make_subscriber<std::string>(
            [&](const std::string& trace)
            {
                std::string asset;
                auto matched = RE2::PartialMatch(trace, *assetNamePattern, &asset);
                m_traceBuffer[asset] = std::make_shared<std::stringstream>(trace + "\n");
            }));
    }
}

} // namespace router
