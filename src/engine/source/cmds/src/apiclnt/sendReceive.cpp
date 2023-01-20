#include "sendReceive.hpp"

#include <exception>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include <uvw/pipe.hpp>
#include <uvw/timer.hpp>

#include <logging/logging.hpp>
#include <utils/stringUtils.hpp>

#include "base/utils/getExceptionStack.hpp"

namespace
{
void client(uvw::Loop& loop,
            const std::string& socketPath,
            const std::string& request,
            std::string& response,
            std::string& error)
{
    auto client = loop.resource<uvw::PipeHandle>();

    client->on<uvw::ErrorEvent>(
        [&error](const uvw::ErrorEvent& event, uvw::PipeHandle& handle)
        {
            error = "Socket communication error: ";
            error += event.what();
            handle.close();
        });

    client->once<uvw::ConnectEvent>(
        [&request](const uvw::ConnectEvent&, uvw::PipeHandle& handle)
        {
            std::vector<char> buffer {request.begin(), request.end()};
            handle.write(buffer.data(), buffer.size());
            handle.read();
        });

    client->on<uvw::DataEvent>(
        [&response](const uvw::DataEvent& event, uvw::PipeHandle& handle)
        {
            response =
                std::string(event.data.get() + sizeof(int), event.length - sizeof(int));
            handle.close();
        });

    client->once<uvw::EndEvent>(
        [](const uvw::EndEvent&, uvw::PipeHandle& handle)
        {
            handle.close();
        });

    // Stablish connection
    client->connect(socketPath);
}

} // namespace

namespace cmd::apiclnt
{

api::WazuhResponse sendReceive(const std::string& socketPath,
                               const api::WazuhRequest& request)
{
    // Prepare request
    auto requestStr = request.toStr();

    // Add protocol header
    int32_t length = requestStr.size();
    std::unique_ptr<char[]> buffer(new char[sizeof(length) + length]);
    std::memcpy(buffer.get(), &length, sizeof(length));
    std::memcpy(buffer.get() + sizeof(length), requestStr.data(), length);
    auto requestWithHeader = std::string(buffer.get(), sizeof(length) + length);

    // Stablish connection, send request and receive response
    std::string response {};
    std::string error {};
    auto loop = uvw::Loop::getDefault();
    client(*loop, socketPath, requestWithHeader, response, error);
    loop->run();

    // Parse response
    if (!error.empty())
    {
        throw std::runtime_error(error);
    }

    api::WazuhResponse parsedResponse;
    try
    {
        parsedResponse = api::WazuhResponse::fromStr(response);
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error("Invalid response from server: "
                                 + std::string(e.what()));
    }

    return parsedResponse;
}

} // namespace cmd::apiclnt
