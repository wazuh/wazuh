#ifndef _METRICS_MANAGERIMP_HPP
#define _METRICS_MANAGERIMP_HPP

#include <chrono>
#include <memory>

#include <base/logging.hpp>
#include <metrics/manager.hpp>

#include "ot.hpp"

namespace metrics
{

struct Manager::ImplConfig : public IManager::Config
{
    ImplConfig()
        : indexerConnectorFactory(nullptr)
        , exportInterval(1000)
        , exportTimeout(333)
        , logLevel(logging::Level::Err)
    {
    }

    ~ImplConfig() override = default;

    ImplConfig(const ImplConfig&) = default;
    ImplConfig(ImplConfig&&) = default;
    ImplConfig& operator=(const ImplConfig&) = default;
    ImplConfig& operator=(ImplConfig&&) = default;

    std::function<std::shared_ptr<IIndexerConnector>()> indexerConnectorFactory;
    std::chrono::milliseconds exportInterval;
    std::chrono::milliseconds exportTimeout;
    logging::Level logLevel;
};

struct Manager::ImplOtPipeline
{
    std::shared_ptr<otsdk::MeterProvider> provider;
};

class Manager::ImplMetric : public IMetric
{
public:
    ~ImplMetric() override = default;

    virtual void create(const Manager::ImplOtPipeline& otPipeline) = 0;

    virtual void destroy() = 0;

    virtual void enable() = 0;

    virtual void disable() = 0;

    virtual bool isEnabled() const = 0;
};

} // namespace metrics

#endif // _METRICS_MANAGERIMP_HPP
