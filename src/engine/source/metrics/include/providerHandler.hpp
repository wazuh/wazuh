#ifndef _PROVIDER_HANDLER_HPP
#define _PROVIDER_HANDLER_HPP

#include "chainOfResponsibility.hpp"
#include "metricsContext.hpp"

class ProviderHandler final : public AbstractHandler<std::shared_ptr<MetricsContext>>
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

#endif // _PROVIDER_HANDLER_HPP
