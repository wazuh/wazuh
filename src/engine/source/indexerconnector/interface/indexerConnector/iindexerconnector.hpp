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
     * @param message The message to be published (must be in JSON string format).
     */
    virtual void publish(const std::string& message) = 0;
};

#endif // _IINDEXER_CONNECTOR_HPP
