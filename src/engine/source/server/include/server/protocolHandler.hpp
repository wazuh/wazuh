#ifndef _SERVER_PROTOCOL_HANDLER_BASE_HPP
#define _SERVER_PROTOCOL_HANDLER_BASE_HPP

#include <memory>
#include <string>
#include <vector>
#include <optional>
#include <tuple>

namespace engineserver
{
class ProtocolHandler
{

public:
    ProtocolHandler() = default;
    virtual ~ProtocolHandler() = default;

    // Se procesa sincronicamente, deberia separar los mensajes
    virtual std::optional<std::vector<std::string>> onData(std::string_view data) = 0;

    // Se procesa asincronicamente, usa como argumento los mensajes generados por onData
    virtual std::string onMessage(const std::string& message) = 0;


    // Tranforma el mensaje en el protocolo para enviarlo, usa el container de string para almacenar el array y el tamano
    virtual std::tuple<std::unique_ptr<char[]>, std::size_t> streamToSend(std::shared_ptr<std::string> message) = 0;

    // Bussy response
    virtual std::tuple<std::unique_ptr<char[]>, std::size_t> getBusyResponse() = 0;

    // Get error response
    virtual std::string getErrorResponse() = 0;

};

// ProtocolHandler Factory
class ProtocolHandlerFactory
{
public:
    ProtocolHandlerFactory() = default;
    virtual ~ProtocolHandlerFactory() = default;

    virtual std::shared_ptr<ProtocolHandler> create() = 0;
};

} // namespace engineserver

#endif // _SERVER_PROTOCOL_HANDLER_BASE_HPP
