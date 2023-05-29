#include <router/runtimePolicy.hpp>

#include <base/parseEvent.hpp>
#include <logging/logging.hpp>
#include <rxbk/rxFactory.hpp>
#include <utils/getExceptionStack.hpp>
#include <regex>

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
        subscribeToOutput();
        listenAllTrace();
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

    return std::nullopt;
}

void RuntimePolicy::subscribeToOutput()
{
    auto subscriber = rxcpp::make_subscriber<rxbk::RxEvent>(
        [&](const rxbk::RxEvent& event) {
            std::lock_guard<std::mutex> lock(m_outputMutex);
            std::stringstream output;
            output << event->payload()->prettyStr() << std::endl;
            m_output = output.str();
        });

    m_spController->getOutput().subscribe(subscriber);
}

void RuntimePolicy::listenAllTrace()
{
    m_spController->listenOnAllTrace(rxcpp::make_subscriber<std::string>(
        [&](const std::string& trace)
        {
            std::lock_guard<std::mutex> lock(m_tracerMutex);
            const std::string opPatternTrace = R"(\[([^\]]+)\] \[condition\]:(.+))";
            const std::regex opRegex(opPatternTrace);
            std::smatch match;
            if (std::regex_search(trace, match, opRegex))
            {
                m_history.push_back({match[1].str(), match[2].str()});
            }
            const std::string opPatternTraceVerbose = R"(^\[([^\]]+)\] (.+))";
            const std::regex opRegexVerbose(opPatternTraceVerbose);
            std::smatch matchVerbose;
            if (std::regex_search(trace, matchVerbose, opRegexVerbose))
            {
                const std::string& key = matchVerbose[1].str();
                std::shared_ptr<std::stringstream> traceStream = std::make_shared<std::stringstream>();
                *traceStream << trace;

                m_traceBuffer[key].push_back(traceStream);
            }
        }));
}

} // namespace router
