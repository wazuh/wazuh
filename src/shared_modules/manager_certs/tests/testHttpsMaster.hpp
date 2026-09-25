/*
 * Wazuh manager certs tool - a real HTTPS master for the component test
 * Copyright (C) 2015, Wazuh Inc.
 * September 19, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _MANAGER_CERTS_TEST_HTTPS_MASTER_HPP
#define _MANAGER_CERTS_TEST_HTTPS_MASTER_HPP

// A `GET /cacerts` that is a REAL TLS server, so the component test can put the compiled binary
// through the one thing no seam can fake: a handshake. Everything the CurlPort seam of
// managerCertsFromMaster_test.cpp asserts is about what libcurl was ASKED for; what a certificate
// signed by the wrong CA, or carrying the wrong identity, or a body that stops halfway actually
// does to the connection can only be seen here (C39h, objection 13).
//
// A bounded COPY of the idiom in src/client-agent/https_client/tests/component/fakeManager.hpp
// (cpp-httplib's SSLServer over an in-memory certificate, a child process the test kills), with
// the same precedent testPki.hpp documents at its own :15-24: a shared module never includes
// another module's test headers. Only what this suite needs is kept, and what it needs that the
// mould does not have is the response shaping -- status, generation header, body size, chunking,
// a deliberately truncated body -- because those are the guards under test.

#include "external/cpp-httplib/httplib.h"

#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>

namespace manager_certs::test
{
    /// How the master answers. Every field is a case of the component test's matrix.
    struct HttpsMasterOptions
    {
        std::string bindAddress {"127.0.0.1"};
        int port {0};                ///< 0: any free port, written to readyFile (no port collisions between cases).
        std::string certificatePath; ///< The listener's own certificate (PEM).
        std::string privateKeyPath;
        std::string bodyPath;   ///< The PEM to serve; empty serves an empty body.
        std::string generation; ///< `Wazuh-CA-Generation`; empty means the header is NOT sent.
        int status {200};
        std::size_t padTo {0};  ///< Pad the body with comment lines up to exactly this many bytes.
        std::size_t chunks {0}; ///< Serve the body in this many chunked pieces (0: one response).
        bool truncate {false};  ///< Promise a longer body than is sent, then drop the connection.
        std::string requestLog; ///< Every requested path is appended here, one per line.
        std::string readyFile;  ///< Created once the socket is bound: the test waits on it.
    };

    /// @p path read whole, or an empty string.
    inline std::string readWhole(const std::string& path)
    {
        if (path.empty())
        {
            return {};
        }
        std::ifstream file {path, std::ios::binary};
        std::ostringstream buffer;
        buffer << file.rdbuf();
        return buffer.str();
    }

    /// @p body padded with comment lines to exactly @p target bytes. Comments are what a PEM reader
    /// skips, so a padded bundle still parses as the certificates it carries -- which is what makes
    /// "exactly 1 MiB is accepted" a test of the cap and not of the parser.
    inline std::string padded(std::string body, std::size_t target)
    {
        while (body.size() < target)
        {
            const std::size_t missing = target - body.size();
            if (missing == 1)
            {
                body.push_back('\n');
                break;
            }
            const std::size_t line = std::min<std::size_t>(64, missing);
            body.append(line - 1, '#');
            body.push_back('\n');
        }
        return body;
    }

    /// Runs the listener until the process is killed. Returns non-zero only when it could not
    /// start, so the test tells "the fixture is broken" from "the tool did not connect".
    inline int runHttpsMaster(const HttpsMasterOptions& options)
    {
        const std::string certificate = readWhole(options.certificatePath);
        const std::string privateKey = readWhole(options.privateKeyPath);
        if (certificate.empty() || privateKey.empty())
        {
            std::fprintf(stderr, "testHttpsMaster: certificate or key missing\n");
            return 2;
        }

        std::string body = readWhole(options.bodyPath);
        if (options.padTo > 0)
        {
            body = padded(std::move(body), options.padTo);
        }

        httplib::SSLServer server {options.certificatePath.c_str(), options.privateKeyPath.c_str()};
        if (!server.is_valid())
        {
            std::fprintf(stderr, "testHttpsMaster: the TLS context is not valid\n");
            return 2;
        }

        server.Get(".*",
                   [&options, &body](const httplib::Request& request, httplib::Response& response)
                   {
                       if (!options.requestLog.empty())
                       {
                           std::ofstream log {options.requestLog, std::ios::app};
                           log << request.path << '\n';
                       }

                       response.status = options.status;
                       if (!options.generation.empty())
                       {
                           response.set_header("Wazuh-CA-Generation", options.generation);
                       }

                       if (options.truncate)
                       {
                           // A Content-Length nobody will ever see the end of: the provider gives
                           // the first half and then refuses, which drops the connection mid-body.
                           const std::size_t promised = body.size() + 4096;
                           response.set_content_provider(
                               promised,
                               "application/x-pem-file",
                               [&body](std::size_t offset, std::size_t /*length*/, httplib::DataSink& sink)
                               {
                                   if (offset >= body.size() / 2)
                                   {
                                       return false; // Aborts the transfer.
                                   }
                                   const std::size_t piece = std::min<std::size_t>(4096, body.size() / 2 - offset);
                                   sink.write(body.data() + offset, piece);
                                   return true;
                               });
                           return;
                       }

                       if (options.chunks > 1)
                       {
                           // Several writes, so a body that only crosses the cap in its LAST piece
                           // reaches the tool's write callback in more than one call (C39c).
                           auto remaining = std::make_shared<std::size_t>(0);
                           const std::size_t pieces = options.chunks;
                           response.set_chunked_content_provider(
                               "application/x-pem-file",
                               [&body, remaining, pieces](std::size_t /*offset*/, httplib::DataSink& sink)
                               {
                                   const std::size_t piece = (body.size() + pieces - 1) / pieces;
                                   if (*remaining >= body.size())
                                   {
                                       sink.done();
                                       return true;
                                   }
                                   const std::size_t bytes = std::min(piece, body.size() - *remaining);
                                   sink.write(body.data() + *remaining, bytes);
                                   *remaining += bytes;
                                   return true;
                               });
                           return;
                       }

                       response.set_content(body, "application/x-pem-file");
                   });

        int bound = options.port;
        if (options.port == 0)
        {
            // Let the kernel pick: two cases of the same run can then never fight over a port, and
            // the test learns which one through the ready file.
            bound = server.bind_to_any_port(options.bindAddress);
            if (bound < 0)
            {
                std::fprintf(stderr, "testHttpsMaster: cannot bind %s\n", options.bindAddress.c_str());
                return 2;
            }
        }
        else if (!server.bind_to_port(options.bindAddress, options.port))
        {
            std::fprintf(stderr, "testHttpsMaster: cannot bind %s:%d\n", options.bindAddress.c_str(), options.port);
            return 2;
        }

        // Bound, so a connection now queues instead of being refused: only here is it honest to
        // tell the test it may run the tool.
        if (!options.readyFile.empty())
        {
            std::ofstream ready {options.readyFile};
            ready << bound << '\n';
        }

        server.listen_after_bind();
        return 0;
    }

} // namespace manager_certs::test

#endif // _MANAGER_CERTS_TEST_HTTPS_MASTER_HPP
