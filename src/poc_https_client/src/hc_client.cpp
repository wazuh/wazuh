/*
 * The C ABI of the HTTPS client — SPIKE #37738 PoC.
 *
 * This file is the entire C↔C++ boundary, the same contract shape the
 * manager-side `remoted_module` uses on 5.0.0-https: the C caller includes
 * only include/hc_client.h, every exported function catches all exceptions
 * (nothing ever throws into C), and everything behind it is C++17
 * (hcClientFacade.*). The opaque hc_handle owns the facade instance.
 */

#include "hc_client.h"
#include "hcClientFacade.hpp"

struct hc_handle
{
    HcClientFacade impl;
    hc_handle(const hc_config_t& cfg, const hc_callbacks_t& cb)
        : impl(cfg, cb)
    {
    }
};

extern "C"
{

    hc_handle* hc_create(const hc_config_t* cfg, const hc_callbacks_t* cb)
    {
        if (!cfg || !cb)
        {
            return nullptr;
        }
        try
        {
            return new hc_handle(*cfg, *cb);
        }
        catch (...)
        {
            return nullptr;
        }
    }

    void hc_destroy(hc_handle* h)
    {
        try
        {
            delete h;
        }
        catch (...)
        {
            /* nothing throws into C */
        }
    }

    bool hc_submit_event(hc_handle* h, const uint8_t* frame, size_t len)
    {
        if (!h || !frame)
        {
            return false;
        }
        try
        {
            return h->impl.submitEvent(frame, len);
        }
        catch (...)
        {
            return false;
        }
    }

    int hc_flush_events(hc_handle* h)
    {
        if (!h)
        {
            return HC_ERROR;
        }
        try
        {
            return h->impl.flushEvents();
        }
        catch (...)
        {
            return HC_ERROR;
        }
    }

    int hc_submit_sync_session(hc_handle* h, const uint8_t* buf, size_t len,
                               const char* session_id, char** result_json_out)
    {
        if (!h || !buf || !session_id)
        {
            return HC_ERROR;
        }
        try
        {
            return h->impl.submitSyncSession(buf, len, session_id, result_json_out);
        }
        catch (...)
        {
            return HC_ERROR;
        }
    }

    int hc_startup(hc_handle* h)
    {
        if (!h)
        {
            return HC_ERROR;
        }
        try
        {
            return h->impl.startup();
        }
        catch (...)
        {
            return HC_ERROR;
        }
    }

    int hc_notify(hc_handle* h)
    {
        if (!h)
        {
            return HC_ERROR;
        }
        try
        {
            return h->impl.notify();
        }
        catch (...)
        {
            return HC_ERROR;
        }
    }

    hc_conn_state_t hc_state(const hc_handle* h)
    {
        if (!h)
        {
            return HC_STATE_STOPPED;
        }
        try
        {
            return h->impl.state();
        }
        catch (...)
        {
            return HC_STATE_STOPPED;
        }
    }

} /* extern "C" */
