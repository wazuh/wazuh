/*
 * Wazuh manager certs tool - `--from-master`
 * Copyright (C) 2015, Wazuh Inc.
 * September 19, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "manager_certs/commands.hpp"
#include "masterTransport.hpp"

#include <ca_bundle/ca_bundle.hpp>

#include <cstddef>
#include <cstdint>
#include <exception>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace manager_certs
{
    namespace
    {
        /// The header `GET /cacerts` announces the generation in
        /// (src/remoted/remoted_module/src/endpoints/cacertsEndpoint.hpp:60, `CA_GENERATION_HEADER`).
        /// Duplicated rather than linked -- this tool must not depend on remoted_module -- and
        /// matched case-insensitively on the way in, as HTTP requires.
        constexpr const char* kGenerationHeader = "Wazuh-CA-Generation";

        /// The route a manager serves its published bundle on, under the configured prefix.
        constexpr const char* kCacertsPath = "/cacerts";

        /// What an operator can do instead when the master cannot be reached: the two knobs that
        /// override the configuration, and the copy-by-hand path that does not need the network.
        constexpr const char* kUnreachableHint =
            "; check that the master's HTTPS listener is up and reachable (override the address with "
            "--master and the port with --port), or copy its bundle across with scp and install it here with "
            "'wazuh-manager-certs add <file>' followed by 'wazuh-manager-certs check'";

        /// @p raw with its trailing slashes dropped and a leading one guaranteed, or empty for the
        /// root. Same criterion as remoted's own normalizeGlobalPrefix()
        /// (src/remoted/remoted_module/src/http_server/httpServerConfig.cpp:208-228), which this
        /// binary cannot link because it is another executable: "" / "/" / "///" all mean no
        /// prefix, so the installed default `/wazuh-manager/` produces `/wazuh-manager/cacerts` and
        /// never `/wazuh-manager//cacerts` (C39g).
        std::string normalizePrefix(std::string_view raw)
        {
            if (raw.find_first_not_of('/') == std::string_view::npos)
            {
                return {};
            }

            std::string prefix;
            if (raw.front() != '/')
            {
                prefix.push_back('/');
            }
            prefix.append(raw);
            while (!prefix.empty() && prefix.back() == '/')
            {
                prefix.pop_back();
            }
            return prefix;
        }

        /// @p host as the authority of a URL: an IPv6 literal wrapped in brackets, anything that
        /// could break out of the authority refused (C39g). Never string concatenation of a value
        /// straight from the configuration.
        std::optional<std::string> authorityOf(const std::string& host, std::string& message)
        {
            if (host.empty())
            {
                message = "no master address configured (/cluster/nodes is empty); pass --master <host>";
                return std::nullopt;
            }

            for (const unsigned char byte : host)
            {
                // Everything that would change which host, port or path is contacted, plus control
                // characters and whitespace. ':' is deliberately allowed: it is what an IPv6
                // literal is made of.
                if (byte <= 0x20 || byte == 0x7F || byte == '/' || byte == '?' || byte == '#' || byte == '@' ||
                    byte == '\\')
                {
                    message = "the master address is not a host name or address: '" + host + "'";
                    return std::nullopt;
                }
            }

            const bool looksBracketed = host.front() == '[' || host.back() == ']';
            if (looksBracketed)
            {
                const bool balanced = host.size() > 2 && host.front() == '[' && host.back() == ']' &&
                                      host.find('[', 1) == std::string::npos && host.find(']') == host.size() - 1;
                if (!balanced)
                {
                    message = "the master address has unbalanced brackets: '" + host + "'";
                    return std::nullopt;
                }
                return host;
            }

            if (host.find(':') != std::string::npos)
            {
                // An IPv6 literal the operator wrote bare (`--master ::1`): the authority needs it
                // bracketed or the first colon reads as the port separator.
                return "[" + host + "]";
            }
            return host;
        }

        /// @p port as digits in 1-65535, or nothing and @p message saying why.
        std::optional<std::string> portOf(const std::string& port, std::string& message)
        {
            const auto refuse = [&message, &port]()
            {
                message = "the master's HTTPS port is not a number in 1-65535: '" + port + "'";
                return std::nullopt;
            };

            if (port.empty() || port.size() > 5)
            {
                return refuse();
            }
            for (const char byte : port)
            {
                if (byte < '0' || byte > '9')
                {
                    return refuse();
                }
            }

            const long value = std::stol(port);
            if (value < 1 || value > 65535)
            {
                return refuse();
            }
            return std::to_string(value);
        }

        /// `https://<authority>:<port><prefix>/cacerts`, built from components (C39g, §7).
        std::optional<std::string> buildUrl(const FromMasterRequest& fetch, std::string& message)
        {
            const std::optional<std::string> authority = authorityOf(fetch.host, message);
            if (!authority)
            {
                return std::nullopt;
            }
            const std::optional<std::string> port = portOf(fetch.port, message);
            if (!port)
            {
                return std::nullopt;
            }
            return "https://" + *authority + ":" + *port + normalizePrefix(fetch.globalPrefix) + kCacertsPath;
        }

        /// @p text as a whole decimal integer, or nothing. Deliberately strict: no sign but '-', no
        /// whitespace, no trailing units, nothing out of range -- a header we cannot read exactly
        /// is a header we do not act on (C38b).
        std::optional<std::int64_t> parseGeneration(const std::string& text)
        {
            if (text.empty() || text.size() > 19)
            {
                return std::nullopt;
            }
            const bool negative = text.front() == '-';
            if (negative && text.size() == 1)
            {
                return std::nullopt;
            }
            for (std::size_t index = negative ? 1U : 0U; index < text.size(); ++index)
            {
                if (text[index] < '0' || text[index] > '9')
                {
                    return std::nullopt;
                }
            }

            try
            {
                return static_cast<std::int64_t>(std::stoll(text));
            }
            catch (const std::exception&)
            {
                return std::nullopt;
            }
        }
    } // namespace

    int runFromMaster(WriteRequest request, FromMasterRequest fetch, std::ostream& out, std::ostream& err)
    {
        const std::string command = request.command.empty() ? std::string {"--from-master"} : request.command;
        const std::string prefix = "wazuh-manager-certs: " + command + ": ";
        const auto refuse = [&err, &prefix](int code, const std::string& text)
        {
            err << prefix << text << '\n';
            return code;
        };

        // Guard 1, G0 and the mirrored G7 (fromMasterEnvironmentFailure()), already ran in main.cpp
        // before anything was opened or locked -- same place and same reason as for the four
        // writing commands (C34c).

        // Guard 2: the lock, BEFORE the local bundle is read and before a single byte goes on the
        // wire (C39d). The CA that authenticates the master's certificate has to be the same CA the
        // transaction publishes over: taken afterwards, a concurrent `remove` could drop the anchor
        // this download was authenticated with between the handshake and the write, and we would
        // install material vouched for by a CA this node had just stopped trusting.
        const std::string bundlePath = request.bundlePath.string();
        PrepareOutcome prepared = prepareWrite(std::move(request));
        if (!prepared.context)
        {
            err << "wazuh-manager-certs: " << prepared.message << '\n';
            return prepared.exitCode;
        }
        WriteContext& context = *prepared.context;

        // Guard 3: the local bundle, as prepareWrite() read it through the descriptor it holds --
        // the bounded (1 MiB) read this tool applies to everything, already under the lock, and not
        // a second read by name that could see another file. Empty means there is nothing to verify
        // the master with: refused HERE, with its own message, because a zero-length blob is
        // exactly what makes libcurl fall back to the system CA store (§1-2).
        if (context.preImage.empty())
        {
            return refuse(2,
                          "the local trust bundle is empty: " + bundlePath +
                              "; there is nothing to verify the master's certificate with (provision it, or copy "
                              "the master's bundle across and install it with 'wazuh-manager-certs add')");
        }

        // Guard 4: the URL, by components (§7).
        std::string message;
        const std::optional<std::string> url = buildUrl(fetch, message);
        if (!url)
        {
            return refuse(2, message);
        }

        // Guard 5: the download itself. Everything that decides what it trusts lives in the
        // transport (§1-6); what arrives here is either a complete 200 or a failure.
        MasterFetch query;
        query.url = *url;
        query.trustBundle = context.preImage;
        query.headerName = kGenerationHeader;
        const MasterTransport transport = fetch.transport.get ? fetch.transport : curlMasterTransport();
        const MasterFetchResult response = transport.get(query);

        // Guard 6: a failed fetch is exit 2 whichever half it failed in, with the two halves told
        // apart in the message -- a refused `setopt` is this build, a refused transfer is the
        // network, the master or its certificate (C39a).
        if (response.failure == MasterFetchFailure::preparation)
        {
            return refuse(2, "cannot prepare the request to " + *url + ": " + response.message);
        }
        if (response.failure == MasterFetchFailure::transfer)
        {
            return refuse(2, "cannot fetch " + *url + ": " + response.message + kUnreachableHint);
        }
        // Defence in depth for C39b: the transport already refuses anything that is not a complete
        // 200, and a transport that ever stopped doing so must not get its body read here either.
        if (response.httpStatus != 200)
        {
            return refuse(
                2, "the master at " + *url + " answered HTTP " + std::to_string(response.httpStatus) + ", not 200");
        }

        // Guard 7: the generation the master announces. Absent and unreadable are both exit 2 --
        // we could not read it, so we cannot act on it -- with different messages, because they are
        // different problems; a readable 0 is exit 1, the master's own bundle is not vouched for
        // (C38b, 02-diseno.md §2.7).
        if (!response.generation)
        {
            return refuse(2,
                          "the master at " + *url + " announces no " + kGenerationHeader +
                              " header; is it running an older version?");
        }
        const std::optional<std::int64_t> generation = parseGeneration(*response.generation);
        if (!generation)
        {
            return refuse(2,
                          "the master's " + std::string {kGenerationHeader} + " header is not a generation: '" +
                              *response.generation + "'");
        }
        if (*generation == 0)
        {
            return refuse(1,
                          "the master's bundle is not vouched for (generation 0); run 'wazuh-manager-certs stamp' "
                          "there first");
        }

        // Guard 8: the same generation this node already serves. Nothing to do, and republishing it
        // would send every agent of this worker back for bytes it already has (C35's reasoning, one
        // command over).
        const std::int64_t previous = context.previousPublication;
        if (*generation == previous)
        {
            out << "already at generation " << previous << "; nothing to do\n";
            return 0;
        }

        // Guard 9: a generation behind the one this node already published. A master restored from
        // a backup would otherwise walk this worker's whole fleet backwards, and an agent that
        // already knows the higher number would never adopt it (C37b).
        if (*generation < previous)
        {
            return refuse(1,
                          "the master publishes generation " + std::to_string(*generation) + ", behind this node's " +
                              std::to_string(previous) + "; refusing to move this worker's agents backwards");
        }

        // Guard 10: the body is untrusted input, parsed exactly like a file an operator handed over
        // (C37c). A document we do not understand whole is not one to publish from (P24: we could
        // not parse it, so exit 2).
        ca_bundle::ParsedBundle downloaded = ca_bundle::parseBundle(response.body);
        if (!downloaded.wellFormed)
        {
            return refuse(2, "the bundle served by " + *url + " is malformed; refusing to write");
        }

        // Guard 11 (RF-17, C39f): the normal body carries no publication block at all -- remoted
        // serialises certificates only (caCertificateSource.cpp:102) -- so the header is the
        // authority. If one IS there (a combined file, an edited bundle, a legacy master), it has
        // to say the same thing, or we do not know which of the two the master meant.
        if (downloaded.block && downloaded.block->publication != *generation)
        {
            return refuse(1,
                          "the bundle served by " + *url + " carries publication " +
                              std::to_string(downloaded.block->publication) + " while its header announces " +
                              std::to_string(*generation) + "; refusing to write");
        }

        // Guard 12: the guards every writing command shares, still under the lock taken in guard 2,
        // with the master's generation instead of this node's clock (only G8 is skipped, C37b): G4,
        // G6 against THIS node's leaf, G5 and GH all run, and any of them may still refuse a bundle
        // the master is perfectly happy with (C39h).
        const std::size_t certificates = downloaded.certificates.size();
        const WriteOutcome outcome = finishWrite(context, std::move(downloaded.certificates), {}, *generation);
        if (outcome.exitCode != 0)
        {
            err << "wazuh-manager-certs: " << outcome.message << '\n';
            return outcome.exitCode;
        }

        if (outcome.durabilityUnknown)
        {
            err << "wazuh-manager-certs: " << outcome.message << '\n';
        }
        out << "installed " << certificates << " certificate(s) from " << *url << "; published generation "
            << outcome.publication << '\n';
        return 0;
    }

} // namespace manager_certs
