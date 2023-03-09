#ifndef _READER_HANDLER_HPP
#define _READER_HANDLER_HPP

#include "chainOfResponsibility.hpp"
#include "metricsContext.hpp"

class ReaderHandler final : public AbstractHandler<std::shared_ptr<MetricsContext>>
{
public:
    /**
     * @brief Trigger for the reader process.
     *
     * @param data Context of metrics.
     * @return std::shared_ptr<MetricsContext>
     */
    virtual std::shared_ptr<MetricsContext> handleRequest(std::shared_ptr<MetricsContext> data);

private:
    /**
     * @brief Create the reader instance.
     *
     * @param data Context of metrics.
     */
    void create(std::shared_ptr<MetricsContext> data);
};

#endif // _READER_HANDLER_HPP
