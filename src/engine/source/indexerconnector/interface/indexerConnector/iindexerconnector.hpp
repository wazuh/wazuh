#ifndef _IINDEXER_CONNECTOR_HPP
#define _IINDEXER_CONNECTOR_HPP

#include <string>

class IIndexerConnector
{

public:
    virtual ~IIndexerConnector() = default;

    /**
     * @brief Publish a message into the queue map.
     *
     * @param message Message to be published.
     */
    virtual void publish(const std::string& message) = 0;
};

#endif // _IINDEXER_CONNECTOR_HPP
