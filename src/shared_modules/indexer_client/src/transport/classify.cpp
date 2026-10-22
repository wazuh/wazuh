/*
 * Wazuh indexer client
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#include "transport/classify.hpp"

namespace indexer_client::detail
{
    const char* toString(TransportCause cause) noexcept
    {
        switch (cause)
        {
            case TransportCause::None: return "none";
            case TransportCause::Timeout: return "timeout";
            case TransportCause::Connect: return "connect";
            case TransportCause::SendError: return "send_error";
            case TransportCause::RecvError: return "recv_error";
            case TransportCause::PartialResponse: return "partial_response";
            case TransportCause::ResponseTooLarge: return "response_too_large";
            case TransportCause::LocalError: return "local_error";
            case TransportCause::Cancelled: return "cancelled";
            case TransportCause::Shutdown: return "shutdown";
            case TransportCause::Tls: return "tls";
            case TransportCause::TlsConfig: return "tls_config";
        }
        return "unknown";
    }

    bool nodeAttributable(TransportCause cause) noexcept
    {
        switch (cause)
        {
            case TransportCause::Timeout:
            case TransportCause::Connect:
            case TransportCause::SendError:
            case TransportCause::RecvError:
            case TransportCause::PartialResponse:
            case TransportCause::Tls: return true;
            default: return false;
        }
    }

    // Numeric CURLcode values (curl 8.20, include/curl/curl.h) so that this table needs no curl header.
    TransportCause classifyCurlCode(int curlCode, bool capTripped) noexcept
    {
        switch (curlCode)
        {
            case 0: return TransportCause::None;             // CURLE_OK
            case 28: return TransportCause::Timeout;         // CURLE_OPERATION_TIMEDOUT
            case 6:                                          // CURLE_COULDNT_RESOLVE_HOST
            case 7: return TransportCause::Connect;          // CURLE_COULDNT_CONNECT
            case 55: return TransportCause::SendError;       // CURLE_SEND_ERROR
            case 52:                                         // CURLE_GOT_NOTHING
            case 56:                                         // CURLE_RECV_ERROR
            case 61: return TransportCause::RecvError;       // CURLE_BAD_CONTENT_ENCODING (undecodable body)
            case 18: return TransportCause::PartialResponse; // CURLE_PARTIAL_FILE
            case 23:                                         // CURLE_WRITE_ERROR: ours only if the cap fired
                return capTripped ? TransportCause::ResponseTooLarge : TransportCause::LocalError;
            case 35:                                    // CURLE_SSL_CONNECT_ERROR (handshake)
            case 60:                                    // CURLE_PEER_FAILED_VERIFICATION (CA, hostname)
            case 98: return TransportCause::Tls;        // CURLE_SSL_CLIENTCERT (the node wants a client cert)
            case 58:                                    // CURLE_SSL_CERTPROBLEM (our certificate or pair)
            case 77:                                    // CURLE_SSL_CACERT_BADFILE (our CA bundle)
            case 53:                                    // CURLE_SSL_ENGINE_NOTFOUND       } unreachable with our
            case 54:                                    // CURLE_SSL_ENGINE_SETFAILED      } options (no SSLENGINE,
            case 59:                                    // CURLE_SSL_CIPHER                } cipher list, CRLFILE,
            case 66:                                    // CURLE_SSL_ENGINE_INITFAILED     } ISSUERCERT, pinned key
            case 82:                                    // CURLE_SSL_CRL_BADFILE           } or VERIFYSTATUS);
            case 83:                                    // CURLE_SSL_ISSUER_ERROR          } listed for
            case 90:                                    // CURLE_SSL_PINNEDPUBKEYNOTMATCH  } completeness
            case 91: return TransportCause::TlsConfig;  // CURLE_SSL_INVALIDCERTSTATUS     }
            default: return TransportCause::LocalError; // 2, 27, 43 and everything else
        }
    }
} // namespace indexer_client::detail
