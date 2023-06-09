#include <router/runtimePolicy.hpp>

#include <base/parseEvent.hpp>
#include <logging/logging.hpp>
#include <regex>
#include <rxbk/rxFactory.hpp>
#include <utils/getExceptionStack.hpp>

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

    return std::nullopt;
}

void RuntimePolicy::subscribeToOutput()
{
    auto subscriber = rxcpp::make_subscriber<rxbk::RxEvent>(
        [&](const rxbk::RxEvent& event)
        {
            std::stringstream output;
            output << event->payload()->prettyStr() << std::endl;
            auto result = m_output.emplace(m_asset, output.str());
            if (!result.second)
            {
                result.first->second = output.str();
            }
        });

    m_spController->getOutput().subscribe(subscriber);
}

void RuntimePolicy::listenAllTrace()
{
    m_spController->listenOnAllTrace(rxcpp::make_subscriber<std::string>(
        [&](const std::string& trace)
        {
            const std::string opPatternTrace = R"(\[([^\]]+)\] \[condition\]:(.+))";
            const std::regex opRegex(opPatternTrace);
            std::smatch match;
            if (std::regex_search(trace, match, opRegex))
            {
                m_history[m_asset].push_back({match[1].str(), match[2].str()});
            }
            const std::string opPatternTraceVerbose = R"(^\[([^\]]+)\] (.+))";
            const std::regex opRegexVerbose(opPatternTraceVerbose);
            std::smatch matchVerbose;
            if (std::regex_search(trace, matchVerbose, opRegexVerbose))
            {
                const std::string& key = matchVerbose[1].str();
                std::shared_ptr<std::stringstream> traceStream = std::make_shared<std::stringstream>();
                *traceStream << trace;

                // Check if an entry with the same key already exists in the first level of m_traceBuffer
                auto outerIt = m_traceBuffer.find(m_asset);
                if (outerIt == m_traceBuffer.end())
                {
                    // There is no entry for m_asset, create a new one
                    std::unordered_map<std::string, std::vector<std::shared_ptr<std::stringstream>>> innerMap;
                    innerMap[key] = std::vector<std::shared_ptr<std::stringstream>> {traceStream};

                    m_traceBuffer[m_asset] = innerMap;
                }
                else
                {
                    // Check if an entry with the same key already exists in the second level of m_traceBuffer
                    auto& innerMap = outerIt->second;
                    auto innerIt = innerMap.find(key);
                    if (innerIt == innerMap.end())
                    {
                        // There is no entry for the key in the second level, create a new one
                        innerMap[key] = std::vector<std::shared_ptr<std::stringstream>> {traceStream};
                    }
                    else
                    {
                        // The key already exists at the second level, add the traceStream to the existing list
                        innerIt->second.push_back(traceStream);
                    }
                }
            }
        }));
}

const std::variant<std::tuple<std::string, std::string>, base::Error>
RuntimePolicy::getData(const std::string& policyName, DebugMode debugMode)
{
    if (debugMode == DebugMode::OUTPUT_AND_TRACES_WITH_DETAILS)
    {
        if (m_history[policyName].empty())
        {
            return base::Error {fmt::format(
                "Policy '{}' has not been configured for trace tracking and output subscription", policyName)};
        }

        auto trace = json::Json {R"({})"};
        for (const auto& [asset, condition] : m_history[policyName])
        {
            if (m_traceBuffer.find(policyName) == m_traceBuffer.end())
            {
                return base::Error {fmt::format(
                    "Policy '{}' has not been configured for trace tracking and output subscription", policyName)};
            }
            auto& tracePair = m_traceBuffer[policyName];
            if (tracePair.find(asset) != tracePair.end())
            {
                auto& traceVector = tracePair[asset];
                std::set<std::string> uniqueTraces; // Set for warehouses single traces
                for (const auto& traceStream : traceVector)
                {
                    uniqueTraces.insert(traceStream->str()); // Insert unique traces in the set
                }
                std::stringstream combinedTrace;
                for (const auto& uniqueTrace : uniqueTraces)
                {
                    combinedTrace << uniqueTrace;
                }
                trace.setString(combinedTrace.str(), std::string("/") + asset);
                tracePair[asset].clear();
            }
        }
        m_history[policyName].clear();
        return std::make_tuple(m_output[policyName], trace.prettyStr());
    }
    else if (debugMode == DebugMode::OUTPUT_AND_TRACES)
    {
        if (m_history[policyName].empty())
        {
            return base::Error {fmt::format(
                "Policy '{}' has not been configured for trace tracking and output subscription", policyName)};
        }

        auto trace = json::Json {R"({})"};
        for (const auto& [asset, condition] : m_history[policyName])
        {
            trace.setString(condition, std::string("/") + asset);
        }
        m_history[policyName].clear();
        return std::make_tuple(m_output[policyName], trace.prettyStr());
    }
    else
    {
        return std::make_tuple(m_output[policyName], std::string());
    }
}

} // namespace router
