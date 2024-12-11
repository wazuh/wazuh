// Copyright (C) 2024 Wazuh Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

#include "apiserver/apiServer.hpp"
#include <gtest/gtest.h>
#include <httplib.h>

TEST(ApiServerTest, Constructor)
{
    // Create an instance of ApiServer
    apiserver::ApiServer apiServer;
    ASSERT_FALSE(apiServer.isRunning());
}

TEST(ApiServerTest, Start)
{
    // Create an instance of ApiServer
    apiserver::ApiServer apiServer;

    // Set the socket path
    std::filesystem::path socketPath = "start.sock";

    // Start the server
    apiServer.start(socketPath);

    ASSERT_TRUE(apiServer.isRunning());

    // Stop the server
    apiServer.stop();

    // Check if the server is stopped
    ASSERT_FALSE(apiServer.isRunning());
}

TEST(ApiServerTest, AddRoute)
{
    // Create an instance of ApiServer
    apiserver::ApiServer apiServer;

    // Set the socket path
    std::filesystem::path socketPath = "addroute.sock";

    // Add a route to the server
    apiServer.addRoute(apiserver::Method::GET,
                       "/api/route",
                       [](const httplib::Request& req, httplib::Response& res)
                       {
                           // Return params and query string
                           std::string response = "GET /api/route\n";
                           for (const auto& [key, value] : req.params)
                           {
                               response.append(key);
                               response.append(": ");
                               response.append(value);
                               response.append("\n");
                           }
                           res.set_content(response, "text/plain");
                       });
    apiServer.addRoute(apiserver::Method::POST,
                       "/api/route",
                       [](const httplib::Request& req, httplib::Response& res)
                       {
                           std::string response = "POST /api/route\n";
                           for (const auto& [key, value] : req.params)
                           {
                               response.append(key);
                               response.append(": ");
                               response.append(value);
                               response.append("\n");
                           }
                           res.set_content(response, "text/plain");
                       });
    apiServer.addRoute(apiserver::Method::PUT,
                       "/api/route",
                       [](const httplib::Request& req, httplib::Response& res)
                       {
                           std::string response = "PUT /api/route\n";
                           for (const auto& [key, value] : req.params)
                           {
                               response.append(key);
                               response.append(": ");
                               response.append(value);
                               response.append("\n");
                           }
                           res.set_content(response, "text/plain");
                       });
    apiServer.addRoute(apiserver::Method::DELETE,
                       "/api/route",
                       [](const httplib::Request& req, httplib::Response& res)
                       {
                           std::string response = "DELETE /api/route\n";
                           for (const auto& [key, value] : req.params)
                           {
                               response.append(key);
                               response.append(": ");
                               response.append(value);
                               response.append("\n");
                           }
                           res.set_content(response, "text/plain");
                       });

    // Start the server
    apiServer.start(socketPath);

    ASSERT_TRUE(apiServer.isRunning());

    httplib::Client client(socketPath, true);
    client.set_address_family(AF_UNIX);
    client.set_connection_timeout(5, 0);

    ASSERT_EQ(client.is_valid(), true);

    httplib::Params params = {{"key1", "value1"}, {"key2", "value2"}};

    auto result = client.Get("/api/route?lorem=ipsum");
    ASSERT_EQ(result->status, 200);
    ASSERT_EQ(result->body, "GET /api/route\nlorem: ipsum\n");

    result = client.Post("/api/route", params);
    ASSERT_EQ(result->status, 200);
    ASSERT_EQ(result->body, "POST /api/route\nkey1: value1\nkey2: value2\n");

    result = client.Put("/api/route", params);
    ASSERT_EQ(result->status, 200);
    ASSERT_EQ(result->body, "PUT /api/route\nkey1: value1\nkey2: value2\n");

    result = client.Delete("/api/route?lorem=ipsum");
    ASSERT_EQ(result->status, 200);
    ASSERT_EQ(result->body, "DELETE /api/route\nlorem: ipsum\n");

    // Stop the server
    apiServer.stop();

    // Check if the server is stopped
    ASSERT_FALSE(apiServer.isRunning());
}

TEST(ApiServerTest, StartDoubleStop)
{
    // Create an instance of ApiServer
    apiserver::ApiServer apiServer;

    // Set the socket path
    std::filesystem::path socketPath = "startdoublestop.sock";

    // Start the server
    apiServer.start(socketPath);

    ASSERT_TRUE(apiServer.isRunning());

    // Stop the server
    apiServer.stop();

    // Check if the server is stopped
    ASSERT_FALSE(apiServer.isRunning());

    // Stop the server again
    apiServer.stop();

    // Check if the server is stopped
    ASSERT_FALSE(apiServer.isRunning());
}

TEST(ApiServerTest, DoubleStart)
{
    // Create an instance of ApiServer
    apiserver::ApiServer apiServer;

    // Set the socket path
    std::filesystem::path socketPath = "doublestart.sock";

    // Start the server
    apiServer.start(socketPath);

    ASSERT_TRUE(apiServer.isRunning());

    // Start the server again
    EXPECT_THROW(apiServer.start(socketPath), apiserver::ServerAlreadyRunningException);

    ASSERT_TRUE(apiServer.isRunning());

    // Stop the server
    apiServer.stop();

    // Check if the server is stopped
    ASSERT_FALSE(apiServer.isRunning());
}

TEST(ApiServerTest, EmptyPath)
{
    // Create an instance of ApiServer
    apiserver::ApiServer apiServer;

    // Set the socket path
    std::filesystem::path socketPath = "";

    // Start the server
    EXPECT_THROW(apiServer.start(socketPath), std::invalid_argument);

    // Check if the server is stopped
    ASSERT_FALSE(apiServer.isRunning());
}
