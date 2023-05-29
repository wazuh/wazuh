#ifndef _ROUTER_RUNTIME_ENVIRONMENT_HPP
#define _ROUTER_RUNTIME_ENVIRONMENT_HPP

#include <logging/logging.hpp>
#include <optional>
#include <string>

#include <builder.hpp>
#include <error.hpp>
#include <rxbk/rxFactory.hpp>

namespace router
{

/**
 * @brief Runtime policy represent an policy in memory, ready to be builed and
 * run
 * @note This class is not thread safe
 */
class RuntimePolicy
{
private:
    std::string m_asset;
    std::shared_ptr<rxbk::Controller> m_spController;
    builder::Policy m_environment;
    
    std::string m_output;
    std::string m_debugMode;
    std::vector<std::pair<std::string, std::string>> m_history;
    std::unordered_map<std::string, std::vector<std::shared_ptr<std::stringstream>>> m_traceBuffer;
    std::mutex m_outputMutex;
    std::mutex m_tracerMutex;
    
public:
    /**
     * @brief Construct a new Runtime Policy object
     *
     * @param asset Asset of the policy
     */
    RuntimePolicy(std::string asset)
        : m_asset {asset}
        , m_spController {}
    {
    }

    ~RuntimePolicy() = default;

    /**
     * @brief Build the policy and instantiate the controller.
     *
     * @param builder Builder to be used for policy creation
     * @return Error message if creation fails
     *
     * @note: This function is not thread safe. Only one policy can be built at a time.
     */
    std::optional<base::Error> build(std::shared_ptr<builder::Builder> builder);

    /**
     * @brief Inyect an event into the policy
     *
     * @param event Event to be inyect
     * @return std::optional<base::Error>
     *
     * @note This function is not thread safe. Only one event at a time, because the expression tree (helper
     * functions) are not thread safe.
     */
    std::optional<base::Error> processEvent(base::Event event);

    /**
     * @brief 
     * 
     */
    void subscribeToOutput();

    /**
     * @brief 
     * 
     */
    void listenAllTrace();

    const std::pair<std::string, std::string> getData()
    {
        auto trace = json::Json {R"({})"};
        for (auto& [asset, condition] : m_history)
        {
            if (0 == m_debugMode.compare("OUTPUT_AND_TRACES_WITH_DETAILS"))
            {
                if (m_traceBuffer.find(asset) != m_traceBuffer.end())
                {
                    auto& traceVector = m_traceBuffer[asset];
                    std::set<std::string> uniqueTraces;  // Set for warehouses single traces
                    for (const auto& traceStream : traceVector)
                    {
                        uniqueTraces.insert(traceStream->str());  // Insert unique traces in the set
                    }
                    std::stringstream combinedTrace;
                    for (const auto& uniqueTrace : uniqueTraces)
                    {
                        combinedTrace << uniqueTrace;
                    }
                    trace.setString(combinedTrace.str(), std::string("/") + asset);
                    m_traceBuffer[asset].clear();
                }
            }
            else if (0 == m_debugMode.compare("OUTPUT_AND_TRACES"))
            {
                trace.setString(condition.c_str(), std::string("/") + asset.c_str());
            }
        }
        if (!m_history.empty())
        {
            m_history.clear();
        }
        return {m_output, trace.prettyStr()};
    }

    /**
     * @brief Set the Debug Mode object
     * 
     * @param debugMode 
     */
    void inline setDebugMode(const std::string& debugMode)
    {
        m_debugMode = debugMode;
    }
};

} // namespace router

#endif // _ROUTER_RUNTIME_ENVIRONMENT_HPP
