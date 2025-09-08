
#ifndef STREAMLOG_ILOGGER_HPP
#define STREAMLOG_ILOGGER_HPP

#include <string>
#include <memory>

namespace streamlog
{

/**
 * @brief Abstract base class for writer event handlers.
 *
 * WriterEvent defines an interface for handling log messages.
 * Derived classes must implement the function call operator to process messages.
 */
class WriterEvent
{
public:
    virtual ~WriterEvent() = default;
    /**
     * @brief Handles a log message, return true if the message was successfully handled, false otherwise.
     */
    virtual bool operator()(std::string&& message) = 0;
};

class ILogManager
{
public:
    virtual ~ILogManager() = default;

    // gets a writer for the specified log channel
    virtual std::shared_ptr<WriterEvent> getWriter(const std::string& name) = 0;
};

}

#endif // STREAMLOG_ILOGGER_HPP
