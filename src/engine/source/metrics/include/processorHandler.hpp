#ifndef _PROCESSOR_HANDLER_HPP
#define _PROCESSOR_HANDLER_HPP

#include "chainOfResponsability.hpp"
#include "metricsContext.hpp"

class ProcessorHandler final : public AbstractHandler<std::shared_ptr<MetricsContext>>
{
public:
    /**
     * @brief Trigger for the normalization process on the metrics context.
     *
     * @param data
     * @return std::shared_ptr<MetricsContext>
     */
    virtual std::shared_ptr<MetricsContext> handleRequest(std::shared_ptr<MetricsContext> data);

private:
    /**
     * @brief
     *
     * @param data
     */
    void create(std::shared_ptr<MetricsContext> data);
};

#endif // _PROCESSOR_HANDLER_HPP
