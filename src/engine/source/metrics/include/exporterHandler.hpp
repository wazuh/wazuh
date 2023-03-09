#ifndef _EXPORTER_HANDLER_HPP
#define _EXPORTER_HANDLER_HPP

#include "chainOfResponsibility.hpp"
#include "metricsContext.hpp"

class ExporterHandler final : public AbstractHandler<std::shared_ptr<MetricsContext>>
{
public:
    /**
     * @brief Trigger for the exporter process.
     *
     * @param data Context of metrics.
     * @return std::shared_ptr<MetricsContext>
     */
    virtual std::shared_ptr<MetricsContext> handleRequest(std::shared_ptr<MetricsContext> data);

private:
    /**
     * @brief Create the exporter instance.
     *
     * @param data Context of metrics.
     */
    void create(std::shared_ptr<MetricsContext> data);
};

#endif // _EXPORTER_HANDLER_HPP
