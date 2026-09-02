/*
 * Wazuh remoted module - POST /enroll endpoint
 * Copyright (C) 2015, Wazuh Inc.
 * August 19, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "enrollmentEndpoint.hpp"

#include "common/requestOutcomeMetrics.hpp"

#include "common/logThrottle.hpp"
#include "control/controlTypes.hpp"    // isValidVersion(), compareVersions() -- shared with /control (D8)
#include "endpoints/endpoint.hpp"      // remoted::endpoints::errorResponseFor() -- shared auth-rejection logging
#include "http_server/headerUtils.hpp" // remoted::http::headerValue() -- case-insensitive lookup
#include "json.hpp"
#include "loggerHelper.h"

#include <arpa/inet.h>
#include <sys/socket.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

using remoted::http::headerValue;

namespace remoted::enrollment
{
    namespace
    {
        constexpr auto ENROLLMENT_ENDPOINT_LOGTAG {"wazuh-manager-remoted:enrollment-endpoint"};

        const LogFn& logFn()
        {
            static const LogFn instance {ENROLLMENT_ENDPOINT_LOGTAG};
            return instance;
        }

        remoted::common::LogThrottle& invalidBodyThrottle()
        {
            static remoted::common::LogThrottle instance;
            return instance;
        }

        remoted::common::LogThrottle& authdErrorThrottle()
        {
            static remoted::common::LogThrottle instance;
            return instance;
        }

        remoted::common::LogThrottle& authdUnavailableThrottle()
        {
            static remoted::common::LogThrottle instance;
            return instance;
        }

        // kMaxEnrollBodySize itself lives in enrollmentEndpoint.hpp now (public): remotedModuleFacade.hpp
        // needs the SAME value to cap BodyDecoder's decoded-size for /enroll's dedicated instance
        // (see makeHandler()'s doc comment on why Open mode needs that extra cap). Applied AFTER
        // decoding here too, so together with that cap this bounds both the compressed wire size
        // AND the decompressed size a decompression-bomb could otherwise produce.
        constexpr std::size_t kMaxNameLength = 128;

        remoted::http::HttpResponse errorResponse(int status, int code, std::string_view message)
        {
            nlohmann::json j;
            j["error"]["code"] = code;
            j["error"]["message"] = std::string(message);
            return remoted::http::HttpResponse::json(status, j.dump());
        }

        // Bridges an EnrollmentAuthenticator rejection to /enroll's own error envelope, while
        // reusing errorResponseFor()'s shared logging discipline (throttled WARN for clock skew,
        // DEBUG2 for plain client faults) so an unauthenticated peer can't flood the log any more
        // here than it could against any other endpoint. code is always 0: none of the AuthError
        // values EnrollmentAuthenticator can return carry a numeric authd code.
        remoted::http::HttpResponse authErrorResponse(remoted::auth::AuthError err)
        {
            const auto logged = remoted::endpoints::errorResponseFor(err);
            auto response = errorResponse(logged.status, 0, remoted::auth::publicErrorFor(err).message);
            // Keep the RFC 6750 challenge errorResponseFor() attaches to every credential 401
            // (`WWW-Authenticate: Bearer`): /enroll swaps the body envelope, not the auth contract.
            for (const auto& [name, value] : logged.headers)
            {
                if (name == "WWW-Authenticate")
                {
                    response.headers.emplace_back(name, value);
                }
            }
            return response;
        }

        bool isValidName(std::string_view name)
        {
            // Mirrors OS_IsValidName() (shared/src/agent_validate_op.c) exactly, which is what the
            // network (port 1515) enrollment path applies (auth.c) -- so both ways an agent can
            // enroll accept exactly the same set of names, and neither mints a name the other
            // would have refused.
            //
            // Note this is STRICTER than what authd's local socket enforces: that socket checks
            // only the storage-safety invariant (is_storable_agent_name() in local-server.c),
            // because its established callers -- manage_agents and the API -- have a longer-
            // standing, more permissive contract that predates this endpoint and must keep
            // working. Enrollment has no such obligation, so it holds the tighter line here rather
            // than relying on the socket's floor. Rejecting locally also means never opening a
            // connection to authd for a name it could not accept anyway.
            //
            // A name outside this charset could corrupt client.keys once written (a space splits
            // into extra fields; a leading '#'/'!' collides with the removed-entry marker
            // convention), or simply never round-trip to a name authd itself would accept.
            if (name.size() < 2 || name.size() > kMaxNameLength)
            {
                return false;
            }
            if (name.front() == '.')
            {
                return false;
            }
            return std::all_of(name.begin(),
                               name.end(),
                               [](unsigned char c) { return std::isalnum(c) || c == '-' || c == '_' || c == '.'; });
        }

        // Syntactic IPv4/IPv6/CIDR check, plus two sentinels neither of which is a real address:
        // "any" (authd's own "no override" value) and "src" (the legacy port 1515 wire protocol's
        // "use the connection's actual source IP instead of whatever I put here" sentinel --
        // os_auth/src/auth.c:208, `IP:'src'`; sent by an agent configured with <use_source_ip> on
        // its own side, mirrored here for the same client-side setting). Not a semantic check --
        // authd's local `add` path re-validates independently (and does NOT understand "src"
        // itself -- see resolveIp() below, which must resolve it before ever reaching authd).
        bool isValidIpOrCidr(std::string_view value)
        {
            if (value == "any" || value == "src")
            {
                return true;
            }

            std::string addr(value);
            std::string prefixPart;
            if (const auto slash = addr.find('/'); slash != std::string::npos)
            {
                // Copied BEFORE resize(), not a string_view into addr's own buffer: resize() to a
                // smaller size does not guarantee the bytes past the new length stay valid (it must
                // rewrite the byte at the new size to '\0', and the standard leaves what's beyond
                // that unspecified) -- a view taken first would work by accident on some libstdc++
                // builds and read invalidated/annotated memory under ASan or a hardened one.
                prefixPart = addr.substr(slash + 1);
                addr.resize(slash);
            }

            int maxPrefix = 0;
            unsigned char buf[16];
            if (inet_pton(AF_INET, addr.c_str(), buf) == 1)
            {
                maxPrefix = 32;
            }
            else if (inet_pton(AF_INET6, addr.c_str(), buf) == 1)
            {
                maxPrefix = 128;
            }
            else
            {
                return false;
            }

            if (prefixPart.empty())
            {
                return true;
            }
            if (!std::all_of(prefixPart.begin(), prefixPart.end(), [](char c) { return c >= '0' && c <= '9'; }))
            {
                return false;
            }
            try
            {
                const int prefix = std::stoi(std::string(prefixPart));
                return prefix >= 0 && prefix <= maxPrefix;
            }
            catch (const std::exception&)
            {
                // All-digit but out of range for int (e.g. a huge prefix string) -> not a valid prefix.
                return false;
            }
        }

        struct ParsedBody
        {
            std::string name;
            std::string version;
            std::optional<std::string> groups;
            std::optional<std::string> ip;
            std::optional<std::string> keyHash;
        };

        // Local validation only -- never authd's own rules. On failure, the string is the (fixed,
        // quote-free) message placed in the response's "message" field. Takes a string_view since
        // the caller passes the (possibly decompressed) Payload's view, not necessarily a std::string.
        std::variant<ParsedBody, std::string> parseAndValidateBody(std::string_view body)
        {
            if (body.empty() || body.size() > kMaxEnrollBodySize)
            {
                return std::string("Missing or invalid request body");
            }

            nlohmann::json j = nlohmann::json::parse(body.data(), body.data() + body.size(), nullptr, false);
            if (j.is_discarded() || !j.is_object())
            {
                return std::string("Malformed JSON body");
            }

            ParsedBody parsed;

            const auto nameIt = j.find("name");
            if (nameIt == j.end() || !nameIt->is_string() || !isValidName(nameIt->get<std::string>()))
            {
                return std::string("Missing or invalid field: name");
            }
            parsed.name = nameIt->get<std::string>();

            const auto versionIt = j.find("version");
            if (versionIt == j.end() || !versionIt->is_string() ||
                !remoted::control::isValidVersion(versionIt->get<std::string>()))
            {
                return std::string("Missing or invalid field: version");
            }
            parsed.version = versionIt->get<std::string>();

            if (const auto it = j.find("groups"); it != j.end() && !it->is_null())
            {
                if (!it->is_string())
                {
                    return std::string("Invalid field: groups");
                }
                parsed.groups = it->get<std::string>();
            }

            if (const auto it = j.find("ip"); it != j.end() && !it->is_null())
            {
                if (!it->is_string() || !isValidIpOrCidr(it->get<std::string>()))
                {
                    return std::string("Invalid field: ip");
                }
                parsed.ip = it->get<std::string>();
            }

            if (const auto it = j.find("key_hash"); it != j.end() && !it->is_null())
            {
                if (!it->is_string())
                {
                    return std::string("Invalid field: key_hash");
                }
                parsed.keyHash = it->get<std::string>();
            }

            return parsed;
        }

        std::string resolveIp(bool useSourceIp, const std::string& remoteIp, const std::optional<std::string>& bodyIp)
        {
            if (useSourceIp)
            {
                return remoteIp;
            }
            // "src" is never forwarded to authd literally: it is not an IP, and authd's local
            // `add` path has no notion of it at all (that sentinel only exists in port 1515's own
            // wire parser, auth.c:208) -- it means "use this HTTPS connection's actual peer
            // address", the one thing /enroll always already knows.
            if (bodyIp == "src")
            {
                return remoteIp;
            }
            if (bodyIp)
            {
                return *bodyIp;
            }
            return "any";
        }

        int httpStatusForAuthdError(int code)
        {
            switch (code)
            {
                case 9001:
                case 9002:
                case 9009: return 500;
                case 9003:
                case 9004:
                case 9005:
                case 9006:
                case 9014:
                case 9017: // invalid name format. Unreachable from here in practice: isValidName()
                           // is strictly tighter than the local socket's storage-safety floor, so
                           // any name authd would reject with 9017 was already refused locally with
                           // a 400. Mapped for completeness, and so the status stays right if the
                           // two checks ever diverge.
                case 9019: // invalid caller-supplied key. Unreachable from here too: self-enrollment
                           // never sends a key (authd generates it); mapped for completeness.
                    return 400;
                case 9007:
                case 9008:
                case 9012: return 409;
                case 9013: // max_agents reached
                case 9015: // worker rejection (remove/get, post cluster-forwarding fix)
                case 9016: // clustered forward to master failed
                    return 503;
                default: return 500;
            }
        }

        remoted::http::HttpResponse mapAuthdResult(const AuthdResult& result, EnrollmentMetrics& metrics)
        {
            if (result.errorCode == 0)
            {
                incAccepted(metrics);
                nlohmann::json j;
                j["id"] = result.id;
                j["name"] = result.name;
                j["ip"] = result.ip;
                j["key"] = result.key;
                return remoted::http::HttpResponse::json(200, j.dump());
            }

            if (result.errorCode > 0)
            {
                incAuthdError(metrics);
                if (const auto throttle = authdErrorThrottle().record())
                {
                    LOGFN_DEBUG1(logFn(),
                                 "authd rejected %llu /enroll request(s) in the last %d s (last code=%d: %s).",
                                 throttle.total,
                                 remoted::common::LogThrottle::kDefaultWindowSeconds,
                                 result.errorCode,
                                 result.message.c_str());
                }
                return errorResponse(httpStatusForAuthdError(result.errorCode), result.errorCode, result.message);
            }

            incAuthdUnavailable(metrics);
            if (const auto throttle = authdUnavailableThrottle().record())
            {
                LOGFN_WARN(logFn(),
                           "%llu /enroll request(s) got no clean answer from authd in the last %d s (last: %s). Is "
                           "authd running and enrollment reachable at its local socket?",
                           throttle.total,
                           remoted::common::LogThrottle::kDefaultWindowSeconds,
                           result.message.c_str());
            }
            return errorResponse(503, -1, "Enrollment service temporarily unavailable");
        }

    } // namespace

    remoted::http::RouteHandler makeHandler(const EnrollmentAuthenticator& authenticator,
                                            AuthdClient& authdClient,
                                            const Config& config,
                                            EnrollmentMetrics& metrics,
                                            std::shared_ptr<const remoted::decoding::IBodyDecoder> bodyDecoder,
                                            remoted::metrics::EndpointHttpMetrics httpMetrics)
    {
        return [&authenticator,
                &authdClient,
                config,
                &metrics,
                bodyDecoder = std::move(bodyDecoder),
                httpMetrics = std::move(httpMetrics)](std::shared_ptr<const remoted::http::HttpRequest> request,
                                                      std::shared_ptr<remoted::http::IHttpResponder> responder)
        {
            // Wrapped once, here, so the status/latency accounting covers every answer below --
            // the five inline rejections AND the one authd's callback delivers on a worker thread
            // -- without repeating an instrumentation line per branch (and without a later branch
            // escaping it). The enrollment counters above stay the WHY; this is the WHAT.
            responder = std::make_shared<remoted::metrics::MeteredResponder>(std::move(responder), httpMetrics);

            if (!config.enrollmentEnabled)
            {
                incDisabled(metrics);
                responder->send(errorResponse(403, 0, "Enrollment is disabled on this manager"));
                return;
            }

            // Parsed here (before authentication), acted on only after it succeeds below -- same
            // ordering AuthGateway uses: nothing is decoded on behalf of an unauthenticated peer
            // (the bearer does not cover the body; the size cap is what authenticate() checks).
            const auto contentEncoding =
                remoted::decoding::parseContentEncoding(headerValue(request->headers, "content-encoding"));

            const auto now = static_cast<std::int64_t>(std::time(nullptr));
            const auto authErr = authenticator.authenticate(headerValue(request->headers, "protocol-version"),
                                                            headerValue(request->headers, "authorization"),
                                                            request->body.size(),
                                                            now);
            if (authErr)
            {
                incRejectedAuth(metrics);
                responder->send(authErrorResponse(*authErr));
                return;
            }

            // Zero-copy view into request->body, kept alive by the request itself -- same
            // technique AuthGateway uses (authGateway.cpp) for the same reason: one physical copy
            // of the wire body, decoding replaces the view in place only on the Zstd path.
            remoted::auth::Payload payload {std::string_view {request->body}, request};
            const auto decodeError = bodyDecoder->decode(contentEncoding, payload);
            if (decodeError != remoted::auth::AuthError::None)
            {
                incRejectedValidation(metrics);
                responder->send(authErrorResponse(decodeError));
                return;
            }

            const auto parsedOrError = parseAndValidateBody(payload.bytes());
            if (std::holds_alternative<std::string>(parsedOrError))
            {
                incRejectedValidation(metrics);
                if (const auto throttle = invalidBodyThrottle().record())
                {
                    LOGFN_DEBUG2(logFn(),
                                 "Rejected %llu invalid /enroll request(s) in the last %d s (last reason: %s).",
                                 throttle.total,
                                 remoted::common::LogThrottle::kDefaultWindowSeconds,
                                 std::get<std::string>(parsedOrError).c_str());
                }
                responder->send(errorResponse(400, 0, std::get<std::string>(parsedOrError)));
                return;
            }
            const auto& parsed = std::get<ParsedBody>(parsedOrError);

            // authd's local `add` path performs no version check at all, so remoted enforces
            // allow_higher_versions itself here, reusing compareVersions() rather than duplicating it.
            if (!config.allowHigherVersions &&
                remoted::control::compareVersions(config.managerVersion, parsed.version) < 0)
            {
                incRejectedValidation(metrics);
                responder->send(errorResponse(400, 0, "Agent version is newer than this manager allows"));
                return;
            }

            AuthdAddRequest addRequest;
            addRequest.name = parsed.name;
            addRequest.ip = resolveIp(config.useSourceIp, request->remoteIp, parsed.ip);
            addRequest.groups = parsed.groups;
            addRequest.keyHash = parsed.keyHash;

            authdClient.addAgent(std::move(addRequest),
                                 [responder, &metrics](AuthdResult result)
                                 { responder->send(mapAuthdResult(result, metrics)); });
        };
    }

} // namespace remoted::enrollment
