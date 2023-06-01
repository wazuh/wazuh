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

enum class DebugMode
{
    ONLY_OUTPUT,
    OUTPUT_AND_TRACES,
    OUTPUT_AND_TRACES_WITH_DETAILS
};

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

    /**
     * @brief Get the Data object
     * 
     * @param debugMode 
     * @return const std::variant<std::string, std::optional<std::string>> 
     */
    const std::tuple<std::string,std::string> getData(DebugMode debugMode);
};

} // namespace router

#endif // _ROUTER_RUNTIME_ENVIRONMENT_HPP
