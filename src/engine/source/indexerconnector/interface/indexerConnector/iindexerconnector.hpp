#ifndef _IINDEXER_CONNECTOR_HPP
#define _IINDEXER_CONNECTOR_HPP

#include <string>

class IIndexerConnector
{

public:
    virtual ~IIndexerConnector() = default;

    /**
     * @brief Publishes a message (in JSON string format) to a persistent queue.
     * This method returns immediately without waiting for the message to be processed.
     *
     * @param message The message to be published (must be in JSON string format). The message is a JSON string that
     * includes the following fields:
     * - operation: The operation to be performed. Currently, the only supported operations are ADD and DELETE.
     * - index: The name of the index to which the data will be sent. Only applicable for the ADD operation.
     * - data: The data to be sent to the index. Only applicable for the ADD operation.
     * - id: The unique identifier of the element.
     */
    virtual void publish(const std::string& message) = 0;
};

#endif // _IINDEXER_CONNECTOR_HPP
