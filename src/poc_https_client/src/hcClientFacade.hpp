/*
 * Wazuh agent HTTPS client facade — SPIKE #37738 PoC (C++17 core).
 *
 * The engine behind the C ABI in include/hc_client.h. It deliberately mirrors
 * the boundary conventions of the manager-side `remoted_module` (5.0.0-https):
 * C++17 internals, a single C-ABI header as the only C↔C++ contact, all
 * exceptions caught at the extern "C" edge (src/hc_client.cpp), injected
 * callbacks for logging and results, cooperative lifecycle. One deliberate
 * difference: remoted_module exposes a Singleton because remoted has exactly
 * one instance; the hc_* ABI is handle-based per the D3 interface draft, so
 * this facade is a plain class owned by the opaque handle.
 *
 * Demonstrates the ADR-1 lean (libcurl engine) and the D5/D6/D9 models:
 *   - two headers per request: protocol-version + Authorization (AES-CMAC)
 *   - /stateless H/E batch accumulation (byte budget + interval)
 *   - /stateful whole-session POST streamed from a spooled file
 *     (CURLOPT_READFUNCTION) so peak memory is flat for large inventories
 *     (the #37738 §6 memory technique)
 *   - synchronous request/response everywhere; retry with re-sign on each
 *     attempt (mandated by the 300 s CMAC window), honor Retry-After
 *   - TLS verification modes per DEC-6 (CA file + hostname)
 *
 * Time is the one impurity a PoC needs; production would inject a clock.
 */

#ifndef HC_CLIENT_FACADE_HPP
#define HC_CLIENT_FACADE_HPP

#include "hc_client.h"

#include <curl/curl.h>

#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>

class HcClientFacade final
{
public:
    HcClientFacade(const hc_config_t& cfg, const hc_callbacks_t& cb);
    ~HcClientFacade();

    HcClientFacade(const HcClientFacade&) = delete;
    HcClientFacade& operator=(const HcClientFacade&) = delete;

    bool submitEvent(const uint8_t* frame, size_t len);
    int flushEvents();
    int submitSyncSession(const uint8_t* buf, size_t len,
                          const std::string& sessionId, char** resultJsonOut);
    int startup();
    int notify();
    hc_conn_state_t state() const;

private:
    /* config deep-copied at the boundary: the C caller's strings are not
     * retained past hc_create (same convention as remoted_module's POD copy) */
    struct Config
    {
        std::string baseUrl;
        std::string agentId;
        std::string agentKeyHex;
        hc_verify_mode_t verifyMode {HC_VERIFY_FULL};
        std::string caPath;
        std::string clientCert;
        std::string clientKey;
        size_t batchSizeBytes {0};
        uint32_t batchIntervalMs {0};
        std::string version;
        std::string configChecksum;
        uint32_t backoffBaseMs {0};
        uint32_t backoffCapMs {0};
        uint32_t requestTimeoutMs {0};
    };

    struct Response
    {
        std::string body;
        long http {0};
        long retryAfter {0};
    };

    void setState(hc_conn_state_t s);
    void logf(int level, const char* fmt, ...);
    void applyTls(CURL* c) const;
    curl_slist* buildHeaders(const std::string& method, const std::string& target,
                             const uint8_t* body, size_t bodyLen,
                             const std::string& sessionHeader) const;
    static int classify(CURLcode cc, long http);
    int postMem(const std::string& target, const uint8_t* body, size_t len,
                Response& resp);
    int postFile(const std::string& target, const std::string& path,
                 const std::string& sessionId, Response& resp);

    Config m_cfg;
    hc_callbacks_t m_cb {};
    hc_conn_state_t m_state {HC_STATE_STARTING};

    /* stateless accumulator: H line is added at flush; events stored as raw
     * "E <frame>\n" text. Bounded; drop-newest on overflow (D6 O-a).
     * The stateless sender thread drains it while agentd's intake thread
     * appends: this is the real cross-thread hand-off (D5 note). One mutex
     * guards the accumulator; state changes take it too. Per-request curl
     * handles are created inside each call, so the three endpoint threads
     * never share a handle. */
    std::string m_acc;
    size_t m_accCap {0};
    unsigned m_accEvents {0};
    std::chrono::steady_clock::time_point m_accSince;
    uint32_t m_backoffMs {0};
    mutable std::mutex m_lock;
};

#endif // HC_CLIENT_FACADE_HPP
